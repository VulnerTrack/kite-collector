package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// onboardingTestHarness provides a fully-configured onboarding handler wired
// against a fresh on-disk SQLite store so each test case operates in
// isolation. The returned mux is the same one that dashboard.Serve would
// produce in production.
type onboardingTestHarness struct {
	mux     *http.ServeMux
	store   *sqlite.SQLiteStore
	wrapKey []byte
}

// newOnboardingHarness spins up an ephemeral store and registers the RFC-0112
// routes. When streamCtrl is nil the handlers fall back to read-only
// streaming mode per R8.
func newOnboardingHarness(t *testing.T, streamCtrl StreamController) *onboardingTestHarness {
	t.Helper()

	st, err := sqlite.New(t.TempDir() + "/ob.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	key, keyErr := newOnboardingWrapKey()
	require.NoError(t, keyErr)

	mux := http.NewServeMux()
	registerOnboardingRoutes(mux, onboardingDeps{
		Store:       st,
		StreamCtrl:  streamCtrl,
		WrapKey:     key,
		AppVersion:  "test",
		Commit:      "deadbeef",
		ProbeClient: &http.Client{Timeout: 500_000_000}, // 500ms
	})
	return &onboardingTestHarness{mux: mux, store: st, wrapKey: key}
}

// do executes a request against the harness mux and returns the recorded
// response so tests can assert on status, headers, and body.
func (h *onboardingTestHarness) do(t *testing.T, method, target string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

// fakeStreamController is an in-memory StreamController used to verify that
// the start/stop wire actually invokes the controller.
type fakeStreamController struct {
	startErr error
	stopErr  error
	state    string
	started  int
	stopped  int
}

func (f *fakeStreamController) Start(_ context.Context) error {
	f.started++
	if f.startErr != nil {
		return f.startErr
	}
	f.state = "running"
	return nil
}

func (f *fakeStreamController) Stop(_ context.Context) error {
	f.stopped++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.state = "stopped"
	return nil
}

func (f *fakeStreamController) Status() StreamStatus {
	return StreamStatus{State: f.state, TotalSent: 1}
}

// ---------------------------------------------------------------------------
// Page / fragment shell
// ---------------------------------------------------------------------------

func TestOnboardingPage_Renders(t *testing.T) {
	h := newOnboardingHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "enroll-fragment")
	assert.Contains(t, body, "check-fragment")
	assert.Contains(t, body, "stream-fragment")
}

func TestEnrollFragment_InitiallyEmpty(t *testing.T) {
	h := newOnboardingHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Before enrollment the form renders without a fingerprint section.
	assert.NotContains(t, rec.Body.String(), "<code title=")
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestHandleEnroll_RoundTrip(t *testing.T) {
	h := newOnboardingHarness(t, nil)

	// Valid POST: both fields present, https URL, 16+ char key.
	form := url.Values{
		"platform_endpoint": {"https://platform.example.com"},
		"api_key":           {"sk-platform-live-ABC-0123456789XYZ"},
	}
	rec := h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	)
	assert.Equal(t, http.StatusOK, rec.Code)

	id, err := h.store.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "https://platform.example.com", id.PlatformEndpoint)
	assert.NotEmpty(t, id.ApiKeyWrapped, "wrapped blob must be persisted")
	assert.NotContains(t, string(id.ApiKeyWrapped), "sk-platform-live", "plaintext key must NOT be stored")

	// R4: the response HTML must NOT include the plaintext key.
	assert.NotContains(t, rec.Body.String(), "sk-platform-live",
		"R4: plaintext api_key must never appear in the response after enroll")
}

func TestHandleEnroll_RejectsBadURL(t *testing.T) {
	h := newOnboardingHarness(t, nil)
	form := url.Values{
		"platform_endpoint": {"not-a-url"},
		"api_key":           {"sk-0123456789ABCDEF01"},
	}
	rec := h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	)
	assert.Equal(t, http.StatusOK, rec.Code, "validation errors render inline, not 4xx")
	assert.Contains(t, rec.Body.String(), "http")
}

func TestHandleEnroll_NoPlaintextLeaksInResponses(t *testing.T) {
	h := newOnboardingHarness(t, nil)

	// Enroll
	form := url.Values{
		"platform_endpoint": {"https://platform.example.com"},
		"api_key":           {"sk-super-secret-key-0123456789ABCDEF"},
	}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	)

	// Re-fetch enroll fragment — it must not contain the plaintext key.
	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	secretRe := regexp.MustCompile(`sk-super-secret-key`)
	assert.False(t, secretRe.MatchString(rec.Body.String()),
		"plaintext key leaked into enroll fragment after enrollment")

	// Support bundle must not contain the plaintext key either.
	rec2 := h.do(t, "GET", "/api/v1/support-bundle", nil, nil)
	assert.False(t, secretRe.MatchString(rec2.Body.String()),
		"plaintext key leaked into support bundle")
}

// ---------------------------------------------------------------------------
// Connection check
// ---------------------------------------------------------------------------

func TestHandleConnectionCheck_SkipsWithoutIdentity(t *testing.T) {
	h := newOnboardingHarness(t, nil)

	rec := h.do(t, "GET", "/api/v1/connection/check", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp connectionCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Probes, 6, "all six probes always reported")

	// With no identity: DNS + TLS + reach + auth + clock + otlp must all
	// SKIP — we never hit the network from the test process.
	for _, p := range resp.Probes {
		assert.Equal(t, "skip", p.Result,
			"probe %s should SKIP when no identity is enrolled, got %q (diag %q)",
			p.Name, p.Result, p.Diagnostic)
	}
	assert.False(t, resp.AllPass, "all_pass=false when every probe skipped")
}

// ---------------------------------------------------------------------------
// Stream toggle
// ---------------------------------------------------------------------------

func TestStreamStatusFragment_ReadOnlyMode(t *testing.T) {
	h := newOnboardingHarness(t, nil) // nil StreamController == read-only R8

	rec := h.do(t, "GET", "/fragments/stream-status", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "not wired", "R8: banner explains the read-only mode")
}

func TestStreamStartStop_InvokesController(t *testing.T) {
	fake := &fakeStreamController{state: "idle"}
	h := newOnboardingHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/stream/start", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, fake.started)
	assert.Equal(t, "running", fake.state)

	rec = h.do(t, "POST", "/api/v1/stream/stop", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, fake.stopped)
	assert.Equal(t, "stopped", fake.state)
}

// ---------------------------------------------------------------------------
// Support bundle
// ---------------------------------------------------------------------------

func TestSupportBundle_GeneratesGzip(t *testing.T) {
	h := newOnboardingHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/support-bundle", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
	// gzip magic bytes
	body := rec.Body.Bytes()
	require.GreaterOrEqual(t, len(body), 2)
	assert.Equal(t, byte(0x1f), body[0])
	assert.Equal(t, byte(0x8b), body[1])
}
