package dashboard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Fixtures
// -------------------------------------------------------------------------

func certSummary(id, agent, status string, notAfter time.Time) pkiCertificateSummary {
	return pkiCertificateSummary{
		ID:                id,
		AgentCode:         agent,
		SubjectCN:         agent + ".host",
		TenantID:          "uabc-cyberlab",
		Status:            status,
		KeyAlgorithm:      "ecdsa-p256",
		FingerprintSHA256: fmt.Sprintf("%064x", len(id)+len(agent)),
		NotAfter:          notAfter.UTC().Format(time.RFC3339),
		IssuedAt:          notAfter.Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

// fakeCertReader implements pkiCertificateReader with scriptable responses.
type fakeCertReader struct {
	rows    []pkiCertificateSummary
	listErr error
	detail  pkiCertificateDetail
	getErr  error
	calls   int
}

func (f *fakeCertReader) List(context.Context, string, string) ([]pkiCertificateSummary, int, error) {
	f.calls++
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return append([]pkiCertificateSummary(nil), f.rows...), len(f.rows), nil
}

func (f *fakeCertReader) Get(context.Context, string, string, string) (pkiCertificateDetail, error) {
	if f.getErr != nil {
		return pkiCertificateDetail{}, f.getErr
	}
	return f.detail, nil
}

func certTestDeps(reader pkiCertificateReader, tokenErr error, certsDir string) onboardingDeps {
	return onboardingDeps{
		Logger:      slog.Default(),
		PKIReader:   reader,
		PKIEndpoint: "http://pki.test",
		CertsDir:    certsDir,
		PKIOperatorToken: func(context.Context) (string, error) {
			if tokenErr != nil {
				return "", tokenErr
			}
			return "operator-token", nil
		},
	}
}

// writeCertTestPEM writes a self-signed agent.pem into dir and returns its
// normalized SHA-256 fingerprint.
func writeCertTestPEM(t *testing.T, dir string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "kite-test-local"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), certPEM, 0o600))

	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	local := buildCertLocalIdentity(dir, time.Now())
	require.True(t, local.HasCert)
	_ = parsed
	return local.FingerprintFull
}

// -------------------------------------------------------------------------
// Derivation
// -------------------------------------------------------------------------

func TestDeriveCertState_Matrix(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		status   string
		notAfter string
		want     string
		label    string
	}{
		{"healthy active", "active", now.Add(60 * 24 * time.Hour).Format(time.RFC3339), certStateActive, "active"},
		{"expiring soon", "active", now.Add(10 * 24 * time.Hour).Format(time.RFC3339), certStateExpiring, "expiring"},
		{"status lag", "active", now.Add(-2 * time.Hour).Format(time.RFC3339), certStateLag, "expired · status lag"},
		{"stored expired", "expired", now.Add(-40 * 24 * time.Hour).Format(time.RFC3339), certStateExpired, "expired"},
		{"revoked", "revoked", now.Add(30 * 24 * time.Hour).Format(time.RFC3339), certStateRevoked, "revoked"},
		{"superseded", "superseded", "", certStateSuperseded, "superseded"},
		{"renewed alias", "renewed", "", certStateSuperseded, "superseded"},
		{"unknown verbatim", "quarantined", "", certStateUnknown, "quarantined"},
		{"empty status", "", "", certStateUnknown, "unknown"},
		{"active with unparseable timestamp", "active", "not-a-time", certStateActive, "active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, label, _, _ := deriveCertState(pkiCertificateSummary{Status: tc.status, NotAfter: tc.notAfter}, now)
			assert.Equal(t, tc.want, state)
			assert.Equal(t, tc.label, label)
		})
	}
}

func TestParsePKITime_AcceptsClickHouseAndRFC3339(t *testing.T) {
	for _, ok := range []string{
		"2026-10-19T08:00:00Z", "2026-10-19T08:00:00.123456789Z",
		"2026-10-19 08:00:00", "2026-10-19 08:00:00.123", "2026-10-19T08:00:00.123",
	} {
		_, parsed := parsePKITime(ok)
		assert.True(t, parsed, ok)
	}
	_, parsed := parsePKITime("yesterday-ish")
	assert.False(t, parsed)
	_, parsed = parsePKITime("")
	assert.False(t, parsed)
}

func TestFingerprintNormalization(t *testing.T) {
	assert.Equal(t, "aabb01", normalizeFingerprint("sha256:AA:BB:01"))
	assert.Equal(t, "aabb01", normalizeFingerprint("AABB01"))
	fp := strings.Repeat("ab", 32)
	short := shortCertFingerprint("sha256:" + strings.ToUpper(fp))
	assert.Equal(t, "abab…abab", short)
}

func TestBuildCertRows_AttentionFirstAndCounts(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	rows, counts := buildCertRows([]pkiCertificateSummary{
		certSummary("00000000-0000-0000-0000-000000000001", "kite-healthy", "active", now.Add(60*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000002", "kite-old", "superseded", now.Add(-10*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000003", "kite-gone", "revoked", now.Add(30*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000004", "kite-soon", "active", now.Add(12*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000005", "kite-lagged", "active", now.Add(-3*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000006", "kite-dead", "expired", now.Add(-14*24*time.Hour)),
	}, "kite-healthy", now)

	order := make([]string, 0, len(rows))
	for _, r := range rows {
		order = append(order, r.StateKey)
	}
	assert.Equal(t, []string{
		certStateRevoked, certStateLag, certStateExpired,
		certStateExpiring, certStateActive, certStateSuperseded,
	}, order, "attention first, history last")

	assert.Equal(t, 2, counts.Active, "expiring certificates still count as active")
	assert.Equal(t, 1, counts.Expiring)
	assert.Equal(t, 2, counts.Expired, "status-lag counts as expired")
	assert.Equal(t, 1, counts.Revoked)
	assert.Equal(t, 1, counts.History)

	for _, r := range rows {
		if r.AgentCode == "kite-healthy" {
			assert.True(t, r.IsLocal)
			assert.Equal(t, "in 60d", r.ExpiresRel)
		}
		if r.StateKey == certStateLag {
			assert.True(t, r.Attention)
			assert.Equal(t, "PKI still says active", r.BadgeNote)
		}
	}
}

func TestRenewalHorizonSVG(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	rows, _ := buildCertRows([]pkiCertificateSummary{
		certSummary("00000000-0000-0000-0000-000000000001", "a", "active", now.Add(10*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000002", "b", "active", now.Add(61*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000003", "c", "active", now.Add(200*24*time.Hour)), // beyond horizon
		certSummary("00000000-0000-0000-0000-000000000004", "d", "revoked", now.Add(5*24*time.Hour)),  // not plotted
	}, "", now)

	svg := string(renewalHorizonSVG(rows, now))
	assert.Contains(t, svg, "<svg")
	assert.Contains(t, svg, "#e8a13d", "inside-30d bucket renders amber")
	assert.Contains(t, svg, "#22c55e", "later bucket renders green")
	assert.Equal(t, 2, strings.Count(svg, "<circle"), "beyond-horizon and revoked rows are not plotted")

	empty := renewalHorizonSVG(nil, now)
	assert.Empty(t, string(empty))
}

// -------------------------------------------------------------------------
// Local identity + cross-check
// -------------------------------------------------------------------------

func TestBuildCertLocalIdentity(t *testing.T) {
	empty := buildCertLocalIdentity(t.TempDir(), time.Now())
	assert.False(t, empty.HasCert)
	assert.Empty(t, empty.ReadError, "a missing agent.pem is normal, not an error")

	dir := t.TempDir()
	now := time.Now()
	writeCertTestPEM(t, dir, now.Add(-30*24*time.Hour), now.Add(60*24*time.Hour))
	local := buildCertLocalIdentity(dir, now)
	require.True(t, local.HasCert)
	assert.Equal(t, "kite-test-local", local.SubjectCN)
	assert.InDelta(t, 59, local.DaysLeft, 1)
	assert.InDelta(t, 66, local.GaugePct, 2, "60 of 90 days remaining ≈ 66%")
	assert.False(t, local.Expired)

	bad := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bad, "agent.pem"), []byte("junk"), 0o600))
	broken := buildCertLocalIdentity(bad, now)
	assert.False(t, broken.HasCert)
	assert.Contains(t, broken.ReadError, "no PEM block")
}

func TestCrossCheckLocalIdentity(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	diskFP := writeCertTestPEM(t, dir, now.Add(-time.Hour), now.Add(60*24*time.Hour))
	local := buildCertLocalIdentity(dir, now)
	local.AgentCode = "kite-me"

	match := certSummary("00000000-0000-0000-0000-00000000000a", "kite-me", "active", now.Add(60*24*time.Hour))
	match.FingerprintSHA256 = strings.ToUpper(diskFP) // case must not matter
	rows, _ := buildCertRows([]pkiCertificateSummary{match}, "kite-me", now)
	crossCheckLocalIdentity(&local, rows)
	assert.Equal(t, "match", local.PKIMatch)

	drift := match
	drift.FingerprintSHA256 = strings.Repeat("77", 32)
	rows, _ = buildCertRows([]pkiCertificateSummary{drift}, "kite-me", now)
	local.PKIMatch = ""
	crossCheckLocalIdentity(&local, rows)
	assert.Equal(t, "drift", local.PKIMatch)
	assert.NotEmpty(t, local.PKIActiveShort)

	other := certSummary("00000000-0000-0000-0000-00000000000b", "kite-someone-else", "active", now.Add(60*24*time.Hour))
	rows, _ = buildCertRows([]pkiCertificateSummary{other}, "kite-me", now)
	local.PKIMatch = ""
	crossCheckLocalIdentity(&local, rows)
	assert.Equal(t, "absent", local.PKIMatch, "no active PKI record for this agent code")
}

// -------------------------------------------------------------------------
// Page modes
// -------------------------------------------------------------------------

func TestCertificatesView_Populated(t *testing.T) {
	now := time.Now()
	reader := &fakeCertReader{rows: []pkiCertificateSummary{
		certSummary("00000000-0000-0000-0000-000000000001", "kite-a", "active", now.Add(60*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000002", "kite-a", "superseded", now.Add(-30*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000003", "kite-b", "revoked", now.Add(30*24*time.Hour)),
	}}
	view := buildCertificatesView(context.Background(), certTestDeps(reader, nil, t.TempDir()),
		&certInventoryCache{}, certPageParams{})

	assert.Equal(t, certModePopulated, view.Mode)
	assert.Equal(t, "uabc-cyberlab", view.Tenant)
	assert.Equal(t, 3, view.Total)
	assert.Len(t, view.Rows, 2, "superseded hidden by default")
	assert.Equal(t, 1, view.Hidden)

	var body strings.Builder
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, view))
	html := body.String()
	assert.Contains(t, html, "Tenant inventory")
	assert.Contains(t, html, "badge-revoked")
	assert.Contains(t, html, "/fragments/certificates/00000000-0000-0000-0000-000000000003")
	assert.Contains(t, html, "Rotation history hidden — 1 superseded certificate")
}

func TestCertificatesView_SignInKeepsLocalCard(t *testing.T) {
	dir := t.TempDir()
	writeCertTestPEM(t, dir, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	deps := certTestDeps(&fakeCertReader{}, errors.New("sign in first"), dir)

	view := buildCertificatesView(context.Background(), deps, &certInventoryCache{}, certPageParams{})
	assert.Equal(t, certModeSignIn, view.Mode)
	assert.Equal(t, "unverified", view.Local.PKIMatch)
	assert.Contains(t, view.SignInURL, "%2Fcertificates", "sign-in must return to this page")

	var body strings.Builder
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, view))
	html := body.String()
	assert.Contains(t, html, "This computer", "local card renders without a session")
	assert.Contains(t, html, "not verified against PKI")
	assert.Contains(t, html, "Sign in with VulnerTrack")
	assert.NotContains(t, html, "Tenant inventory", "no inventory table while signed out")
}

func TestCertificatesView_SessionExpiredShowsStaleInventory(t *testing.T) {
	now := time.Now()
	reader := &fakeCertReader{rows: []pkiCertificateSummary{
		certSummary("00000000-0000-0000-0000-000000000001", "kite-a", "active", now.Add(60*24*time.Hour)),
	}}
	cache := &certInventoryCache{}
	deps := certTestDeps(reader, nil, t.TempDir())

	first := buildCertificatesView(context.Background(), deps, cache, certPageParams{})
	require.Equal(t, certModePopulated, first.Mode)

	reader.listErr = errPKICertificateSignInRequired
	second := buildCertificatesView(context.Background(), deps, cache, certPageParams{})
	assert.Equal(t, certModeSessionGone, second.Mode)
	assert.NotEmpty(t, second.StaleAt)
	assert.Len(t, second.Rows, 1, "last good inventory kept")

	var body strings.Builder
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, second))
	assert.Contains(t, body.String(), "session expired")
	assert.Contains(t, body.String(), second.StaleAt)
}

func TestCertificatesView_SessionExpiredWithoutCacheFallsBackToSignIn(t *testing.T) {
	reader := &fakeCertReader{listErr: errPKICertificateSignInRequired}
	view := buildCertificatesView(context.Background(), certTestDeps(reader, nil, t.TempDir()),
		&certInventoryCache{}, certPageParams{})
	assert.Equal(t, certModeSignIn, view.Mode)
	assert.Contains(t, view.Error, "expired")
}

func TestCertificatesView_ErrorAndEmptyAndUnavailable(t *testing.T) {
	errView := buildCertificatesView(context.Background(),
		certTestDeps(&fakeCertReader{listErr: errors.New("dial tcp: i/o timeout")}, nil, t.TempDir()),
		&certInventoryCache{}, certPageParams{})
	assert.Equal(t, certModeError, errView.Mode)
	var body strings.Builder
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, errView))
	assert.Contains(t, body.String(), "PKI is unreachable")
	assert.Contains(t, body.String(), "Retry")
	assert.Contains(t, body.String(), "kite-collector doctor")

	emptyView := buildCertificatesView(context.Background(),
		certTestDeps(&fakeCertReader{}, nil, t.TempDir()), &certInventoryCache{}, certPageParams{})
	assert.Equal(t, certModeEmpty, emptyView.Mode)
	body.Reset()
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, emptyView))
	assert.Contains(t, body.String(), "No certificates issued for this tenant yet")
	assert.Contains(t, body.String(), "Enroll this computer")

	unavailable := buildCertificatesView(context.Background(),
		onboardingDeps{Logger: slog.Default()}, &certInventoryCache{}, certPageParams{})
	assert.Equal(t, certModeUnavailable, unavailable.Mode)
	body.Reset()
	require.NoError(t, certificatesFragmentTmpl.Execute(&body, unavailable))
	assert.Contains(t, body.String(), "unavailable in this dashboard mode")
}

func TestCertificatesView_FiltersAndHistory(t *testing.T) {
	now := time.Now()
	reader := &fakeCertReader{rows: []pkiCertificateSummary{
		certSummary("00000000-0000-0000-0000-000000000001", "kite-a", "active", now.Add(60*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000002", "kite-b", "revoked", now.Add(30*24*time.Hour)),
		certSummary("00000000-0000-0000-0000-000000000003", "kite-c", "superseded", now.Add(-30*24*time.Hour)),
	}}
	deps := certTestDeps(reader, nil, t.TempDir())

	revokedOnly := buildCertificatesView(context.Background(), deps, &certInventoryCache{}, certPageParams{Filter: "revoked"})
	require.Len(t, revokedOnly.Rows, 1)
	assert.Equal(t, certStateRevoked, revokedOnly.Rows[0].StateKey)

	historyOnly := buildCertificatesView(context.Background(), deps, &certInventoryCache{}, certPageParams{Filter: "history", ShowHistory: true})
	require.Len(t, historyOnly.Rows, 1)
	assert.Equal(t, certStateSuperseded, historyOnly.Rows[0].StateKey)

	withHistory := buildCertificatesView(context.Background(), deps, &certInventoryCache{}, certPageParams{ShowHistory: true})
	assert.Len(t, withHistory.Rows, 3)
	assert.Zero(t, withHistory.Hidden)

	// Clicking the active filter chip clears it.
	assert.Equal(t, "/certificates", revokedOnly.ChipURL("revoked"))
	assert.Contains(t, revokedOnly.ChipURL("active"), "filter=active")
}

func TestCertPageURLs(t *testing.T) {
	assert.Equal(t, "/fragments/certificates", certFragmentURL(certPageParams{}))
	u := certFragmentURL(certPageParams{Filter: "expired", ShowHistory: true, Paused: true})
	assert.Contains(t, u, "filter=expired")
	assert.Contains(t, u, "history=1")
	assert.Contains(t, u, "paused=1")
	assert.Equal(t, "/certificates?filter=history", certPageURL(certPageParams{Filter: "history", ShowHistory: true}),
		"filter=history implies history visibility without a redundant param")
}

// -------------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------------

func TestRoute_CertificatesFragmentAndDrawer(t *testing.T) {
	now := time.Now()
	reader := &fakeCertReader{
		rows: []pkiCertificateSummary{
			certSummary("00000000-0000-0000-0000-000000000001", "kite-a", "active", now.Add(60*24*time.Hour)),
		},
		detail: pkiCertificateDetail{
			pkiCertificateSummary: certSummary("00000000-0000-0000-0000-000000000001", "kite-a", "active", now.Add(60*24*time.Hour)),
			CertPEM:               "-----BEGIN CERTIFICATE-----",
		},
	}
	mux := http.NewServeMux()
	registerCertificatesRoutes(mux, certTestDeps(reader, nil, t.TempDir()))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/certificates?filter=active", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Tenant inventory")
	assert.Contains(t, rec.Body.String(), `hx-get="/fragments/certificates?filter=active"`,
		"auto-refresh preserves the filter")

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/certificates/00000000-0000-0000-0000-000000000001", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "row-drawer-head")
	assert.Contains(t, rec.Body.String(), "BEGIN CERTIFICATE")

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/certificates/not-a-uuid", nil))
	require.Equal(t, http.StatusOK, rec.Code, "drawer errors stay drawer-shaped")
	assert.Contains(t, rec.Body.String(), "Invalid certificate ID")
	assert.Contains(t, rec.Body.String(), "closeRowDrawer()")
}

func TestRoute_CertificatesPageShellCarriesQuery(t *testing.T) {
	var buf strings.Builder
	require.NoError(t, renderCertificatesPageFragment(&buf, "filter=revoked"))
	assert.Contains(t, buf.String(), `hx-get="/fragments/certificates?filter=revoked"`)
	assert.Contains(t, buf.String(), "cert-skel", "shell shows the skeleton until the fragment lands")
}
