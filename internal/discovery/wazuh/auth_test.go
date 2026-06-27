package wazuh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Mock auth server
// -------------------------------------------------------------------------

func newMockAuthServer(t *testing.T, username, password, token string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		u, p, ok := r.BasicAuth()
		if !ok || u != username || p != password {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":1,"message":"Unauthorized"}`))
			return
		}

		resp := struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}{}
		resp.Data.Token = token

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestAuth_GetToken_Success(t *testing.T) {
	srv := newMockAuthServer(t, "admin", "secret", "test-jwt-token")
	defer srv.Close()

	auth := newAuth(srv.URL, "admin", "secret", srv.Client())

	token, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-jwt-token", token)
}

func TestAuth_GetToken_Cached(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}{}
		resp.Data.Token = "cached-token"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	auth := newAuth(srv.URL, "user", "pass", srv.Client())

	// First call — authenticates.
	tok1, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cached-token", tok1)

	// Second call — should use cache.
	tok2, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cached-token", tok2)

	assert.Equal(t, 1, calls, "should only authenticate once")
}

func TestAuth_GetToken_RefreshOnExpiry(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}{}
		resp.Data.Token = "refreshed-token"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	auth := newAuth(srv.URL, "user", "pass", srv.Client())

	// Get initial token.
	_, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	// Simulate token about to expire (within buffer).
	auth.mu.Lock()
	auth.expiry = time.Now().Add(30 * time.Second) // within 60s buffer
	auth.mu.Unlock()

	// Should refresh.
	tok, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "refreshed-token", tok)
	assert.Equal(t, 2, calls, "should re-authenticate when token near expiry")
}

func TestAuth_GetToken_BadCredentials(t *testing.T) {
	srv := newMockAuthServer(t, "admin", "correct", "token")
	defer srv.Close()

	auth := newAuth(srv.URL, "admin", "wrong", srv.Client())

	_, err := auth.getToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestAuth_InvalidateToken(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}{}
		resp.Data.Token = "new-token"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	auth := newAuth(srv.URL, "user", "pass", srv.Client())

	_, err := auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	// Invalidate forces re-auth.
	auth.invalidateToken()

	_, err = auth.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

func TestAuth_IsDefaultCredentials(t *testing.T) {
	auth1 := newAuth("https://example.com", "wazuh", "wazuh", http.DefaultClient)
	assert.True(t, auth1.isDefaultCredentials())

	auth2 := newAuth("https://example.com", "admin", "strongpass", http.DefaultClient)
	assert.False(t, auth2.isDefaultCredentials())
}
