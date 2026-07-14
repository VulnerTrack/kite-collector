// OAuth 2.1 authorization-code + PKCE sign-in for agent enrollment
// (RFC-0127 direction). The agent is a public client: no client secret
// ships in the binary. The code exchange is secured by the PKCE
// verifier, which lives in process memory for one login attempt and is
// never written to disk or logs — a pasted authorization code is
// useless without it.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OAuthConfig identifies the IdP authorize/token endpoints for the
// sign-in flow. Issuer is the auth base URL, e.g.
// https://<project>.supabase.co/auth/v1 — the endpoints are derived as
// <issuer>/oauth/authorize and <issuer>/oauth/token.
type OAuthConfig struct {
	Issuer      string
	ClientID    string
	RedirectURI string
	Scope       string
}

// PKCE holds one login attempt's verifier/challenge pair (RFC 7636,
// S256). The verifier must never leave process memory.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a fresh high-entropy verifier and its S256
// challenge. The verifier is 43 base64url chars (32 random bytes), the
// RFC 7636 minimum length.
func NewPKCE() (*PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return &PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// NewState generates the opaque state parameter echoed back through
// the redirect, letting the CLI detect a code minted for a different
// login attempt.
func NewState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// AuthorizeURL builds the browser sign-in URL the operator opens.
func (c OAuthConfig) AuthorizeURL(challenge, state string) (string, error) {
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURI == "" {
		return "", fmt.Errorf("issuer, client_id, and redirect_uri are required")
	}
	u, err := url.Parse(strings.TrimRight(c.Issuer, "/") + "/oauth/authorize")
	if err != nil {
		return "", fmt.Errorf("parse issuer URL: %w", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	if c.Scope != "" {
		q.Set("scope", c.Scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Token is the token-endpoint response. The access token is a
// short-lived JWT presented once as the enrollment credential; hold it
// in memory only.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// OAuthClient exchanges authorization codes at the IdP token endpoint.
type OAuthClient struct {
	http httpDoer
}

// NewOAuthClient creates a token-endpoint client.
func NewOAuthClient() *OAuthClient {
	return &OAuthClient{http: http.DefaultClient}
}

// ExchangeCode redeems a single-use authorization code plus the PKCE
// verifier for an access token. Public-client exchange: no client
// secret is sent.
func (o *OAuthClient) ExchangeCode(ctx context.Context, cfg OAuthConfig, code, verifier string) (*Token, error) {
	if code == "" {
		return nil, fmt.Errorf("authorization code is empty")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}
	endpoint := strings.TrimRight(cfg.Issuer, "/") + "/oauth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	doer := o.http
	if doer == nil {
		doer = http.DefaultClient
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Body carries the OAuth error (invalid_grant, expired code, ...);
		// it never echoes the code or verifier, so it is safe to surface.
		return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, data)
	}

	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token response contained no access_token")
	}
	return &tok, nil
}
