package dashboard

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveKiteOAuthLaunchURL only ever dereferences api.vulnertrack.com;
// every other host — and every failure mode — returns the input
// untouched, so the function can never introduce a new destination.
func TestResolveKiteOAuthLaunchURL_NonVulnertrackHostsPassThrough(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "https://example.com/auth",
		resolveKiteOAuthLaunchURL(ctx, "https://example.com/auth"),
		"non-api hosts are never contacted")
	assert.Equal(t, "http://127.0.0.1:1/x",
		resolveKiteOAuthLaunchURL(ctx, "http://127.0.0.1:1/x"))
	assert.Equal(t, "://bad", resolveKiteOAuthLaunchURL(ctx, "://bad"),
		"unparseable URLs pass through unchanged")
}

// The redirect-allowlist: only app.vulnertrack.com and the configured
// authorize host may be redirect destinations; schemes without hosts
// (javascript:, data:) are rejected outright.
func TestIsAllowedKiteLaunchURL(t *testing.T) {
	oauth := OAuthOptions{AuthorizeURL: "https://auth.example.com/oauth/authorize"}

	assert.True(t, isAllowedKiteLaunchURL(oauth, "https://app.vulnertrack.com/kite/signin/oauth/x"))
	assert.True(t, isAllowedKiteLaunchURL(oauth, "https://auth.example.com/anything"),
		"the configured authorize host is trusted")
	assert.False(t, isAllowedKiteLaunchURL(oauth, "https://evil.example.net/"))
	assert.False(t, isAllowedKiteLaunchURL(oauth, "javascript:alert(1)"))
	assert.False(t, isAllowedKiteLaunchURL(oauth, "data:text/html,x"))
	assert.False(t, isAllowedKiteLaunchURL(oauth, "://bad"))

	// Default authorize URL → api.vulnertrack.com is the trusted host.
	assert.True(t, isAllowedKiteLaunchURL(OAuthOptions{}, "https://api.vulnertrack.com/auth/v1/oauth/authorize"))
}

// The DevTools copy-paste recovery: &-escaped state markers embedded
// in the code parameter are split back out.
func TestKiteOAuthCallbackCodeAndState(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET",
		"http://127.0.0.1/oauth/callback?code=abc&state=xyz", nil)
	code, state := kiteOAuthCallbackCodeAndState(req)
	assert.Equal(t, "abc", code)
	assert.Equal(t, "xyz", state)

	// Operator pasted the DevTools-escaped value: the whole thing lands
	// in code as `abc&state=recovered` and must be split back out.
	req = httptest.NewRequestWithContext(context.Background(), "GET",
		"http://127.0.0.1/oauth/callback?code=abc%5Cu0026state=recovered", nil)
	code, state = kiteOAuthCallbackCodeAndState(req)
	assert.Equal(t, "abc", code, "the escaped marker is stripped from code")
	assert.Equal(t, "recovered", state)

	// Doubly-encoded variant: code carries the literal %5Cu0026state= text.
	req = httptest.NewRequestWithContext(context.Background(), "GET",
		"http://127.0.0.1/oauth/callback?code=abc%255Cu0026state%3Dalsorecovered", nil)
	code, state = kiteOAuthCallbackCodeAndState(req)
	assert.Equal(t, "abc", code)
	assert.Equal(t, "alsorecovered", state)

	req = httptest.NewRequestWithContext(context.Background(), "GET",
		"http://127.0.0.1/oauth/callback?code=abc", nil)
	code, state = kiteOAuthCallbackCodeAndState(req)
	assert.Equal(t, "abc", code)
	assert.Empty(t, state, "no marker, no state")
}

func TestResolveKiteOAuthTokenURL(t *testing.T) {
	got, err := resolveKiteOAuthTokenURL(OAuthOptions{
		AuthorizeURL: "https://auth.example.com/v1/oauth/authorize?x=1#frag",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/v1/oauth/token", got,
		"authorize swaps to token; query and fragment dropped")

	got, err = resolveKiteOAuthTokenURL(OAuthOptions{})
	require.NoError(t, err)
	assert.Equal(t, "https://api.vulnertrack.com/auth/v1/oauth/token", got)

	_, err = resolveKiteOAuthTokenURL(OAuthOptions{AuthorizeURL: "https://x.example.com/oauth/login"})
	require.Error(t, err, "URLs not ending in /authorize are rejected")

	_, err = resolveKiteOAuthTokenURL(OAuthOptions{AuthorizeURL: "://bad"})
	require.Error(t, err)
}

func TestBuildKiteOAuthRedirectURI(t *testing.T) {
	got, err := buildKiteOAuthRedirectURI("http://127.0.0.1:9090", "")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:9090/oauth/callback", got,
		"empty path takes the default callback path")

	got, err = buildKiteOAuthRedirectURI("https://host.example.com/base/", "cb")
	require.NoError(t, err)
	assert.Equal(t, "https://host.example.com/base/cb", got,
		"missing leading slash is added, trailing base slash collapsed")

	_, err = buildKiteOAuthRedirectURI("ftp://host/", "")
	require.Error(t, err, "non-http schemes are rejected")
	_, err = buildKiteOAuthRedirectURI("not a url", "")
	require.Error(t, err)
	_, err = buildKiteOAuthRedirectURI("", "")
	require.Error(t, err)
}
