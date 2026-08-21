package enrollment

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeURL_UnparseableIssuer(t *testing.T) {
	cfg := OAuthConfig{
		Issuer:      "https://idp.example/\x00",
		ClientID:    "client-123",
		RedirectURI: "https://app.example/cli-auth",
	}
	_, err := cfg.AuthorizeURL("challenge", "state")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse issuer URL")
}

func TestExchangeCode_UnparseableIssuerFailsRequestCreation(t *testing.T) {
	c := NewOAuthClient()
	c.http = &captureDoer{}

	_, err := c.ExchangeCode(
		context.Background(),
		OAuthConfig{Issuer: "https://idp.example/\x00"},
		"code",
		"verifier",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create token request")
}

func TestExchangeCode_BodyReadFailure(t *testing.T) {
	c := NewOAuthClient()
	c.http = &captureDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errReader{}),
	}}

	_, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "code", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read token response")
}

func TestExchangeCode_MalformedTokenResponse(t *testing.T) {
	c := NewOAuthClient()
	c.http = &captureDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":`)),
	}}

	_, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "code", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode token response")
}

// TestExchangeCode_ZeroValueClientUsesDefaultTransport exercises the nil-doer
// fallback against a loopback token endpoint.
func TestExchangeCode_ZeroValueClientUsesDefaultTransport(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"jwt-x","token_type":"bearer","expires_in":60}`))
	}))
	t.Cleanup(srv.Close)

	c := &OAuthClient{} // zero value: nil http falls back to http.DefaultClient
	tok, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: srv.URL}, "code", "v")
	require.NoError(t, err)
	assert.Equal(t, "jwt-x", tok.AccessToken)
	assert.Equal(t, 60, tok.ExpiresIn)
	assert.Equal(t, "/oauth/token", gotPath)
}
