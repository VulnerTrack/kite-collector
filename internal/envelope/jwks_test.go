package envelope

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jwksServer(t *testing.T, keys *jose.JSONWebKeySet, status *atomic.Int32, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if s := status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func publicJWK(t *testing.T, kid, use string) jose.JSONWebKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: k.Public(), KeyID: kid, Algorithm: string(KeyAlgorithm), Use: use}
}

func TestJWKSClient_PicksEncryptionKeyAndCaches(t *testing.T) {
	var status, hits atomic.Int32
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		publicJWK(t, "sig-1", "sig"),
		publicJWK(t, "enc-1", "enc"),
	}}
	srv := jwksServer(t, set, &status, &hits)
	c := NewJWKSClient(srv.URL, nil)

	key, err := c.GetEncryptionKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "enc-1", key.KeyID, "use=enc wins over use=sig")
	assert.True(t, key.IsPublic())

	_, err = c.GetEncryptionKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load(), "second call within TTL is served from cache")

	byID, err := c.GetKey(context.Background(), "sig-1")
	require.NoError(t, err)
	assert.Equal(t, "sig-1", byID.KeyID)

	_, err = c.GetKey(context.Background(), "missing")
	require.Error(t, err)
}

func TestJWKSClient_RefreshFailureKeepsCachedKey(t *testing.T) {
	var status, hits atomic.Int32
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK(t, "enc-1", "enc")}}
	srv := jwksServer(t, set, &status, &hits)
	c := NewJWKSClient(srv.URL, nil)
	c.ttl = time.Nanosecond // force staleness on every call

	_, err := c.GetEncryptionKey(context.Background())
	require.NoError(t, err)

	status.Store(http.StatusBadGateway)
	key, err := c.GetEncryptionKey(context.Background())
	require.NoError(t, err, "a stale cache beats no key while the JWKS endpoint is down")
	assert.Equal(t, "enc-1", key.KeyID)
}

func TestJWKSClient_NoCacheAndFetchFails(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(http.StatusInternalServerError)
	srv := jwksServer(t, &jose.JSONWebKeySet{}, &status, &hits)
	c := NewJWKSClient(srv.URL, nil)

	_, err := c.GetEncryptionKey(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestJWKSClient_EmptySetIsAnError(t *testing.T) {
	var status, hits atomic.Int32
	srv := jwksServer(t, &jose.JSONWebKeySet{}, &status, &hits)
	c := NewJWKSClient(srv.URL, nil)
	_, err := c.GetEncryptionKey(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no keys")
}

// TestJWKSClient_SealsEndToEnd: the production wiring — Sealer over a
// JWKSClient — produces envelopes the key's owner can open.
func TestJWKSClient_SealsEndToEnd(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: serverKey.Public(), KeyID: "gw-1", Algorithm: string(KeyAlgorithm), Use: "enc"},
	}}
	var status, hits atomic.Int32
	srv := jwksServer(t, set, &status, &hits)

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sealer, err := NewSealer(SigningKey{Key: agentKey, KeyID: "agent"}, NewJWKSClient(srv.URL, nil))
	require.NoError(t, err)

	sealed, err := sealer.Seal(context.Background(), []byte("otlp"), "application/json")
	require.NoError(t, err)
	assert.Equal(t, "gw-1", sealed.KeyID)

	opened, err := Open(sealed.Compact, jose.JSONWebKey{Key: serverKey, KeyID: "gw-1"}, agentKey.Public())
	require.NoError(t, err)
	assert.Equal(t, []byte("otlp"), opened.Payload)
}
