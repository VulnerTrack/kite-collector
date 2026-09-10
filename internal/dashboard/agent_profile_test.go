package dashboard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// writeAgentCert writes a self-signed agent.pem into dir with the identity
// fields PKI stamps at enrollment: tenant in O, user in OU, email as SAN,
// client name as CN.
func writeAgentCert(t *testing.T, dir string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName:         "agent-code-42",
			Organization:       []string{"11111111-1111-4111-8111-111111111111", "Northwind Traders"},
			OrganizationalUnit: []string{"33333333-3333-4333-8333-333333333333"},
		},
		EmailAddresses: []string{"operator@example.com"},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0o600))
}

func TestAgentProfile_RegistrationCardReadsTheCertificate(t *testing.T) {
	certsDir := t.TempDir()
	now := time.Now()
	writeAgentCert(t, certsDir, now.Add(-26*24*time.Hour), now.Add(64*24*time.Hour))

	view := buildObservabilityView(context.Background(), onboardingDeps{
		CertsDir:         certsDir,
		PlatformEndpoint: "otel.example.test:4317",
		TLSConfig:        config.TLSConfig{Enabled: true, CertFile: filepath.Join(certsDir, "agent.pem")},
	})
	require.True(t, view.Certificate.Present)
	assert.Equal(t, "agent-code-42", view.Certificate.SubjectCN)
	assert.Equal(t, 64, view.Certificate.DaysLeft)
	assert.False(t, view.Certificate.Expired)
	assert.Empty(t, view.Certificate.WindowClass, "64 days left is not yet a warning")
	assert.True(t, view.Certificate.MutualTLS)
	assert.Equal(t, "Northwind Traders", view.TenantOrgName)

	var rendered strings.Builder
	require.NoError(t, observabilityTmpl.Execute(&rendered, view))
	body := rendered.String()
	assert.Contains(t, body, `id="section-registration"`)
	assert.Contains(t, body, "Valid to "+now.Add(64*24*time.Hour).UTC().Format("2 Jan 2006"))
	assert.Contains(t, body, "64 days left, issued")
	assert.Contains(t, body, "over mutual TLS")
	assert.Contains(t, body, "Northwind Traders")
	assert.Contains(t, body, "operator@example.com")
	// Identifiers card: certificate-derived values with their attribute names.
	assert.Contains(t, body, `id="section-identifiers"`)
	assert.Contains(t, body, "agent-code-42")
	assert.Contains(t, body, "certificate CN")
	assert.Contains(t, body, "11111111-1111-4111-8111-111111111111")
	assert.Contains(t, body, "tenant.id, certificate O")
}

func TestAgentProfile_CertificateWindowWarnsAndExpires(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeAgentCert(t, dir, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	soon := readAgentCertificate(filepath.Join(dir, "agent.pem"), now)
	assert.Equal(t, "profile-note-warn", soon.WindowClass, "inside the 30-day renewal window the note is amber")
	assert.Equal(t, 10, soon.DaysLeft)

	dir2 := t.TempDir()
	writeAgentCert(t, dir2, now.Add(-100*24*time.Hour), now.Add(-time.Hour))
	gone := readAgentCertificate(filepath.Join(dir2, "agent.pem"), now)
	assert.True(t, gone.Expired)
	assert.Equal(t, 0, gone.DaysLeft)
	assert.Equal(t, "profile-note-error", gone.WindowClass)
	assert.True(t, strings.HasPrefix(gone.WindowNote, "expired, issued"))

	missing := readAgentCertificate(filepath.Join(t.TempDir(), "agent.pem"), now)
	assert.False(t, missing.Present)
}

func TestAgentProfile_NoCertificateRendersEmptyStates(t *testing.T) {
	view := buildObservabilityView(context.Background(), onboardingDeps{CertsDir: t.TempDir()})
	var rendered strings.Builder
	require.NoError(t, observabilityTmpl.Execute(&rendered, view))
	body := rendered.String()
	assert.Contains(t, body, "no client certificate")
	assert.Contains(t, body, "not enrolled")
	assert.Contains(t, body, "without a client certificate")
	assert.Contains(t, body, "not yet assigned", "the agent id row says so when identity.json is absent")
}

func TestAgentProfile_IdentifiersReadAgentIDWithoutMintingOne(t *testing.T) {
	dir := t.TempDir()
	assert.Empty(t, readAgentID(dir))
	_, err := os.Stat(filepath.Join(dir, "identity.json"))
	assert.True(t, os.IsNotExist(err), "reading the agent id must never create identity.json")

	id := uuid.Must(uuid.NewV7())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "identity.json"),
		[]byte(`{"agent_id":"`+id.String()+`","public_key":"","private_key":""}`), 0o600))
	assert.Equal(t, id.String(), readAgentID(dir))

	// identity dir resolution mirrors the CLI: configured dir, else the db dir.
	deps := onboardingDeps{DBPath: filepath.Join(dir, "kite.db")}
	assert.Equal(t, dir, identityDirFor(deps))
	deps.BaseConfig = &config.Config{}
	deps.BaseConfig.Identity.DataDir = "/elsewhere"
	assert.Equal(t, "/elsewhere", identityDirFor(deps))
	assert.Empty(t, identityDirFor(onboardingDeps{}))
}

func TestAgentProfile_SoftwareCardCarriesBuildAndPlatform(t *testing.T) {
	st := collectAgentState(onboardingDeps{AppVersion: "v1.4.2", Commit: "9288b52"})
	assert.Equal(t, "kite-collector", st.Name)
	assert.Equal(t, "kite-collector", st.AgentType)
	assert.Equal(t, "Vulnertrack", st.Vendor)
	assert.NotEmpty(t, st.Platform)
	assert.NotEmpty(t, st.Architecture)
	assert.NotEmpty(t, st.ContractVersion)
	assert.True(t, strings.HasPrefix(st.BinaryHash, "sha256:"), "the running test binary hashes like any other executable")
}

func TestAgentProfile_ThisHostCardLinksToTheMachine(t *testing.T) {
	h := newInstallHarness(t, nil)
	hostname, err := os.Hostname()
	require.NoError(t, err)

	// Before any scan the card explains itself instead of showing blanks.
	rec := h.do(t, "GET", "/agent", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "No scan has recorded this host yet")

	// A network scan row for the same name and the agent probe's own row:
	// the card must pick the agent's.
	now := time.Now().UTC()
	other := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, MachineType: model.MachineTypeServer,
		OSFamily: "linux", DiscoverySource: "network_scan", FirstSeenAt: now, LastSeenAt: now,
		IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
	}
	other.ComputeNaturalKey()
	self := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, MachineType: model.MachineTypeWorkstation,
		OSFamily: "linux", OSVersion: "arch rolling", KernelVersion: "7.1.5-zen1-2-zen", Architecture: "amd64",
		DiscoverySource: "agent", FirstSeenAt: now, LastSeenAt: now,
		IsAuthorized: model.AuthorizationAuthorized, IsManaged: model.ManagedUnknown,
	}
	self.ComputeNaturalKey()
	require.NoError(t, h.store.UpsertMachine(context.Background(), other))
	require.NoError(t, h.store.UpsertMachine(context.Background(), self))
	require.NoError(t, h.store.UpsertSoftware(context.Background(), self.ID, []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), MachineID: self.ID, SoftwareName: "openssh", Version: "9.9p1"},
		{ID: uuid.Must(uuid.NewV7()), MachineID: self.ID, SoftwareName: "curl", Version: "8.10"},
	}))

	rec = h.do(t, "GET", "/agent", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `id="section-host"`)
	assert.Contains(t, body, "<strong>"+hostname+"</strong>")
	assert.Contains(t, body, "7.1.5-zen1-2-zen")
	assert.Contains(t, body, `href="/machines/`+self.ID.String()+`"`,
		"Explore this machine must open the agent's own machine record")
	assert.NotContains(t, body, `href="/machines/`+other.ID.String()+`"`,
		"the network-scan row for the same name must not win over the agent's row")
	assert.Contains(t, body, `>2 <span class="muted small">packages</span>`,
		"the software count comes from the introspection total for this machine")
	assert.Contains(t, body, `>0 <span class="muted small">on this host</span>`,
		"the findings count renders even when it is zero")
}

func TestAgentProfile_SnapshotCarriesTheNewFields(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	for _, key := range []string{"certificate", "identifiers", "agent"} {
		assert.Contains(t, doc, key, "snapshot must carry %q so scripted monitoring sees what the page shows", key)
	}
	var agent map[string]any
	require.NoError(t, json.Unmarshal(doc["agent"], &agent))
	assert.Equal(t, "kite-collector", agent["agent_type"])
	assert.Contains(t, agent, "binary_hash")
}

func TestSidebar_EntriesWithoutTablesRenderNoCountBadge(t *testing.T) {
	// Docs, Onboarding and the agent profile have no backing table. They used
	// to render a "0" badge because the zero value passed the >= 0 check.
	tree := string(renderSidebarTreeStatic("agent"))
	for _, label := range []string{"Agent profile", "Docs", "Onboarding", "Mass deployment", "Certificates"} {
		i := strings.Index(tree, ">"+label+"</span>")
		require.Greater(t, i, -1, "sidebar must list %s", label)
		tail := tree[i : i+len(label)+40]
		assert.NotContains(t, tail, `sidenav-count">0<`, "%s must not carry a zero badge: %s", label, tail)
	}
	assert.Contains(t, tree, `href="/agent" hx-get="/agent" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`,
		"the profile entry must be marked active when it is the current tab")
	assert.NotContains(t, tree, "<h4></h4>", "a group without a title must not render an empty heading")
}

func TestDashboardShell_TopbarActionClusterOrder(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/agent", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Health pill, Onboarding, divider, then the scan cluster: the primary
	// action lands at the right edge of the bar.
	badge := strings.Index(body, `id="onboarding-status-badge"`)
	onboarding := strings.Index(body, `hx-get="/onboarding" hx-target="#content" hx-push-url="true"
       onclick="setActive(this)">Onboarding</a>`)
	divider := strings.Index(body, `class="topbar-divider"`)
	scan := strings.Index(body, `id="scan-status"`)
	require.True(t, badge > 0 && onboarding > 0 && divider > 0 && scan > 0, "every cluster member must render")
	assert.True(t, badge < onboarding && onboarding < divider && divider < scan,
		"cluster order must be health, Onboarding, divider, scan")
	assert.NotContains(t, body, "/fragments/scan-controls",
		"the button now renders inside the scan-status fragment; no second fragment to keep in step")
	assert.Contains(t, body, `class="scan-cluster"`)
}
