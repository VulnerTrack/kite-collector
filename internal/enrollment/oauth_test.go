package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPKCE_ChallengeIsS256OfVerifier(t *testing.T) {
	p, err := NewPKCE()
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(p.Verifier), 43, "RFC 7636 minimum verifier length")
	sum := sha256.Sum256([]byte(p.Verifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), p.Challenge)
}

func TestNewPKCE_VerifiersAreUnique(t *testing.T) {
	a, err := NewPKCE()
	require.NoError(t, err)
	b, err := NewPKCE()
	require.NoError(t, err)
	assert.NotEqual(t, a.Verifier, b.Verifier)
}

func TestAuthorizeURL_CarriesPKCEAndClientParams(t *testing.T) {
	cfg := OAuthConfig{
		Issuer:      "https://proj.supabase.co/auth/v1/",
		ClientID:    "client-123",
		RedirectURI: "https://app.vulnertrack.io/cli-auth",
		Scope:       "openid email",
	}
	raw, err := cfg.AuthorizeURL("challenge-abc", "state-xyz")
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "/auth/v1/oauth/authorize", u.Path, "trailing issuer slash must not double up")

	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "client-123", q.Get("client_id"))
	assert.Equal(t, "https://app.vulnertrack.io/cli-auth", q.Get("redirect_uri"))
	assert.Equal(t, "challenge-abc", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "state-xyz", q.Get("state"))
	assert.Equal(t, "openid email", q.Get("scope"))
}

func TestAuthorizeURL_RejectsIncompleteConfig(t *testing.T) {
	_, err := OAuthConfig{Issuer: "https://x", ClientID: "c"}.AuthorizeURL("ch", "st")
	require.Error(t, err)
}

// captureDoer records the outgoing request so the exchange form can be
// asserted, and returns a canned response.
type captureDoer struct {
	req  *http.Request
	resp *http.Response
	err  error
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
	d.req = req
	return d.resp, d.err
}

func TestExchangeCode_SendsPublicClientForm(t *testing.T) {
	doer := &captureDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"jwt-abc","token_type":"bearer","expires_in":3600}`)),
	}}
	c := NewOAuthClient()
	c.http = doer

	cfg := OAuthConfig{
		Issuer:      "https://proj.supabase.co/auth/v1",
		ClientID:    "client-123",
		RedirectURI: "https://app.vulnertrack.io/cli-auth",
	}
	tok, err := c.ExchangeCode(context.Background(), cfg, "auth-code", "verifier-xyz")
	require.NoError(t, err)
	assert.Equal(t, "jwt-abc", tok.AccessToken)
	assert.Equal(t, 3600, tok.ExpiresIn)

	require.NotNil(t, doer.req)
	assert.Equal(t, "https://proj.supabase.co/auth/v1/oauth/token", doer.req.URL.String())
	assert.Equal(t, "application/x-www-form-urlencoded", doer.req.Header.Get("Content-Type"))

	body, err := io.ReadAll(doer.req.Body)
	require.NoError(t, err)
	form, err := url.ParseQuery(string(body))
	require.NoError(t, err)
	assert.Equal(t, "authorization_code", form.Get("grant_type"))
	assert.Equal(t, "auth-code", form.Get("code"))
	assert.Equal(t, "verifier-xyz", form.Get("code_verifier"))
	assert.Equal(t, "client-123", form.Get("client_id"))
	assert.Empty(t, form.Get("client_secret"), "public client must never send a secret")
}

func TestExchangeCode_SurfacesOAuthError(t *testing.T) {
	c := NewOAuthClient()
	c.http = &captureDoer{resp: &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)),
	}}

	_, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "stale-code", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestExchangeCode_NetworkFailurePropagates(t *testing.T) {
	c := NewOAuthClient()
	c.http = &captureDoer{err: errors.New("dial tcp: connection refused")}

	_, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "code", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestExchangeCode_RejectsEmptyCodeAndEmptyToken(t *testing.T) {
	c := NewOAuthClient()

	_, err := c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "", "v")
	require.Error(t, err, "empty code must fail before any network call")

	c.http = &captureDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"token_type":"bearer"}`)),
	}}
	_, err = c.ExchangeCode(context.Background(), OAuthConfig{Issuer: "https://x"}, "code", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no access_token")
}
