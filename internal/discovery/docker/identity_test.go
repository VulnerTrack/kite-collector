package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func osArchive(t *testing.T, kind byte, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	h := &tar.Header{Name: "os-release", Mode: 0o644, Typeflag: kind}
	if kind == tar.TypeReg {
		h.Size = int64(len(data))
	}
	require.NoError(t, w.WriteHeader(h))
	if kind == tar.TypeReg {
		_, err := w.Write([]byte(data))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestImageAndContainerIdentityReadOnly(t *testing.T) {
	symlink := osArchive(t, tar.TypeSymlink, "")
	regular := osArchive(t, tar.TypeReg, "ID=debian\nVERSION_ID=\"12\"\nSECRET=do-not-emit\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		switch r.URL.Path {
		case "/v1.43/images/abc/json":
			_, _ = w.Write([]byte(`{"Parent":"sha256:parent","Config":{"Labels":{"org.opencontainers.image.base.name":"debian:12","org.opencontainers.image.base.digest":"sha256:digest","secret":"do-not-emit"}}}`))
		case "/v1.43/containers/abc/archive":
			if r.URL.Query().Get("path") == "/etc/os-release" {
				_, _ = w.Write(symlink)
			} else {
				require.Equal(t, "/usr/lib/os-release", r.URL.Query().Get("path"))
				_, _ = w.Write(regular)
			}
		default:
			t.Errorf("unexpected operation: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	c := newClient(server.URL)
	require.Equal(t, map[string]string{
		"image_base_name": "debian:12", "image_base_digest": "sha256:digest", "image_parent_id": "sha256:parent",
	}, c.imageIdentity(context.Background(), "sha256:abc"))
	require.Equal(t, map[string]string{"os_id": "debian", "os_version_id": "12"}, c.containerOSIdentity(context.Background(), "abc"))
}

func TestIdentityUnavailableAndOversized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.43/images/large/json" {
			_, _ = w.Write(bytes.Repeat([]byte("x"), (1<<20)+1))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	c := newClient(server.URL)
	require.Empty(t, c.imageIdentity(context.Background(), "large"))
	require.Empty(t, c.imageIdentity(context.Background(), "missing"))
	require.Empty(t, c.containerOSIdentity(context.Background(), "missing"))
	require.Empty(t, c.containerOSIdentity(context.Background(), "../escape"))
}

func TestOSReleaseDoesNotEvaluateShell(t *testing.T) {
	facts := parseOSIdentity([]byte("ID='alpine'\nVERSION_ID=\"3.20\"\nCPE_NAME=\"cpe:2.3:o:alpinelinux:alpine_linux:3.20:*:*:*:*:*:*:*\"\nIGNORED=$(env)\n"))
	require.Len(t, facts, 3)
	require.Equal(t, "alpine", facts["os_id"])
	require.Equal(t, "3.20", facts["os_version_id"])
}
