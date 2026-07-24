package ubuntumatrix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitRepository(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{"docker.io/library/ubuntu", "docker.io", "library/ubuntu"},
		{"ubuntu", "docker.io", "library/ubuntu"},
		{"vulnertrack/kite", "docker.io", "vulnertrack/kite"},
		{"ghcr.io/vulnertrack/kite", "ghcr.io", "vulnertrack/kite"},
		{"localhost:5000/kite", "localhost:5000", "kite"},
	} {
		host, path := SplitRepository(tc.in)
		require.Equal(t, tc.wantHost, host, tc.in)
		require.Equal(t, tc.wantPath, path, tc.in)
	}
}

func TestParseChallenge(t *testing.T) {
	params := parseChallenge(
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"`,
	)
	require.Equal(t, "https://auth.docker.io/token", params["realm"])
	require.Equal(t, "registry.docker.io", params["service"])
	require.Equal(t, "repository:library/ubuntu:pull", params["scope"])
}

// The full anonymous-pull flow: an unauthenticated HEAD gets a 401 with a
// Bearer challenge, the client exchanges it for a token, and the retried HEAD
// carries the digest.
func TestResolveTagDigestFollowsAuthChallenge(t *testing.T) {
	const want = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	// Recorded rather than asserted inline: testify's FailNow must run on
	// the test goroutine, not the server's. The mutex matters because
	// `go test -race` (make test-race) does not model happens-before
	// through a socket, so an unguarded write here reads as a data race.
	var mu sync.Mutex
	var authHits, manifestHits int
	var gotAccept, gotScope, gotPath, gotMethod, gotAuthorization string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/token" {
			authHits++
			gotScope = r.URL.Query().Get("scope")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"anon-token"}`))
			return
		}

		manifestHits++
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAccept = r.Header.Get("Accept")

		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+serverTokenURL(r)+`",service="registry.test",scope="repository:library/ubuntu:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Docker-Content-Digest", want)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &RegistryClient{HTTP: srv.Client(), BaseURL: srv.URL}
	got, err := client.ResolveTagDigest(context.Background(), "docker.io/library/ubuntu", "22.04")

	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, 1, authHits)
	require.Equal(t, 2, manifestHits)
	require.Equal(t, "repository:library/ubuntu:pull", gotScope)
	require.Equal(t, http.MethodHead, gotMethod)
	require.Equal(t, "/v2/library/ubuntu/manifests/22.04", gotPath)
	require.Equal(t, "Bearer anon-token", gotAuthorization)

	// Without the index media types a registry answers with a
	// platform-specific manifest, whose digest is not what the tag resolves
	// to — the drift check would then fire on every single run.
	require.Contains(t, gotAccept, "application/vnd.oci.image.index.v1+json")
	require.Contains(t, gotAccept, "manifest.list.v2+json")
}

func TestResolveTagDigestWithoutAuth(t *testing.T) {
	const want = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Docker-Content-Digest", want)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &RegistryClient{BaseURL: srv.URL}
	got, err := client.ResolveTagDigest(context.Background(), "ghcr.io/vulnertrack/kite", "latest")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestResolveTagDigestSurfacesRegistryErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &RegistryClient{BaseURL: srv.URL}
	_, err := client.ResolveTagDigest(context.Background(), "docker.io/library/ubuntu", "nope")
	require.ErrorContains(t, err, "unexpected status 404")
}

func TestResolveTagDigestRejectsMissingDigestHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &RegistryClient{BaseURL: srv.URL}
	_, err := client.ResolveTagDigest(context.Background(), "docker.io/library/ubuntu", "22.04")
	require.ErrorContains(t, err, "no Docker-Content-Digest")
}

func TestNewRegistryClientHasBoundedTimeout(t *testing.T) {
	c := NewRegistryClient()
	require.Equal(t, registryTimeout, c.HTTP.Timeout)
	require.Equal(t, dockerRegistryBase, c.baseURL(defaultRegistryHost))
	require.Equal(t, "https://ghcr.io", c.baseURL("ghcr.io"))
}

// serverTokenURL rebuilds the test server's /token endpoint from the request
// it is answering, so the handler does not need the server value it is
// defined inside.
func serverTokenURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + strings.TrimSuffix(r.Host, "/") + "/token"
}
