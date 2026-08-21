package dashboard

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func enrollTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func postEnroll(t *testing.T, deps onboardingDeps, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://127.0.0.1/fragments/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleEnroll(rec, req, deps)
	return rec
}

// handleEnroll's guard ladder: read-only mode, missing wrap key, and the
// direct-sign-in captcha requirements each stop with a specific message
// before any credential leaves the process.
func TestHandleEnroll_GuardLadder(t *testing.T) {
	rec := postEnroll(t, onboardingDeps{Logger: enrollTestLogger()}, url.Values{})
	assert.Contains(t, rec.Body.String(), "Read-only",
		"nil store means the read-only dashboard cannot enroll")

	st := testStore(t).(*sqlite.SQLiteStore)
	rec = postEnroll(t, onboardingDeps{Logger: enrollTestLogger(), Store: st, WrapKey: []byte("short")}, url.Values{})
	assert.Contains(t, rec.Body.String(), "no wrap key",
		"a non-32-byte wrap key is a server misconfiguration")

	deps := onboardingDeps{Logger: enrollTestLogger(), Store: st, WrapKey: make([]byte, 32)}
	rec = postEnroll(t, deps, url.Values{"email": {"a@b.c"}, "password": {"pw"}})
	assert.Contains(t, rec.Body.String(), "captcha configuration",
		"direct sign-in without a Turnstile site key is refused")

	deps.OAuth.TurnstileSiteKey = "site-key"
	rec = postEnroll(t, deps, url.Values{"email": {"a@b.c"}, "password": {"pw"}})
	assert.Contains(t, rec.Body.String(), "captcha challenge",
		"a missing captcha token is refused before contacting Supabase")
}

// loginToSupabase over httptest: exact request shape (apikey header,
// captcha metadata, password grant), token extraction, and the error
// payload preference order.
func TestLoginToSupabase(t *testing.T) {
	ctx := context.Background()

	_, err := loginToSupabase(ctx, "", "anon", "e", "p", "")
	require.Error(t, err, "missing URL")
	_, err = loginToSupabase(ctx, "http://x", "", "e", "p", "")
	require.Error(t, err, "missing anon key")

	var captured struct {
		apikey string
		body   map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/auth/v1/token", r.URL.Path)
		require.Equal(t, "password", r.URL.Query().Get("grant_type"))
		captured.apikey = r.Header.Get("apikey")
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-123"})
	}))
	defer srv.Close()

	tok, err := loginToSupabase(ctx, srv.URL, "anon-key", "a@b.c", "pw", "captcha-tok")
	require.NoError(t, err)
	assert.Equal(t, "tok-123", tok)
	assert.Equal(t, "anon-key", captured.apikey)
	assert.Equal(t, "a@b.c", captured.body["email"])
	sec, _ := captured.body["gotrue_meta_security"].(map[string]any)
	require.NotNil(t, sec, "captcha token travels in gotrue_meta_security")
	assert.Equal(t, "captcha-tok", sec["captcha_token"])

	// Error payload preference: error_description > msg > error > status.
	errSrv := func(body string, status int) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	_, err = loginToSupabase(ctx, errSrv(`{"error_description":"bad credentials"}`, 400), "k", "e", "p", "")
	assert.EqualError(t, err, "bad credentials")
	_, err = loginToSupabase(ctx, errSrv(`{"msg":"captcha failed"}`, 400), "k", "e", "p", "")
	assert.EqualError(t, err, "captcha failed")
	_, err = loginToSupabase(ctx, errSrv(`{"error":"invalid_grant"}`, 400), "k", "e", "p", "")
	assert.EqualError(t, err, "invalid_grant")
	_, err = loginToSupabase(ctx, errSrv(`not json`, 500), "k", "e", "p", "")
	assert.EqualError(t, err, "auth server returned status 500")

	_, err = loginToSupabase(ctx, errSrv(`{"access_token":""}`, 200), "k", "e", "p", "")
	require.Error(t, err, "an empty access token is rejected")
	_, err = loginToSupabase(ctx, errSrv(`not json`, 200), "k", "e", "p", "")
	require.Error(t, err, "a 200 with garbage body is rejected")
}
