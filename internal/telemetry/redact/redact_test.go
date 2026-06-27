package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsForbidden_BlocksCredentialPatterns(t *testing.T) {
	cases := []string{
		"password",
		"db_password",
		"DB_PASSWORD",
		"some.passwd.here",
		"secret",
		"client_secret",
		"api_key",
		"apiKey",
		"api-key",
		"private_key",
		"privateKey",
		"private-key",
		"authorization",
		"http.request.header.authorization",
		"auth_token",
		"bearer_token",
		"session_id",
		"sessionid",
		"cookie",
		"http.request.header.cookie",
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			assert.Truef(t, IsForbidden(k), "expected %q to be forbidden", k)
		})
	}
}

func TestIsForbidden_BlocksExactKeys(t *testing.T) {
	cases := []string{"env", "ENV", "environ", "command", "cmdline", "argv", "token", "key"}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			assert.Truef(t, IsForbidden(k), "expected %q to be forbidden", k)
		})
	}
}

func TestIsForbidden_BlocksPrefixes(t *testing.T) {
	cases := []string{
		"internal.foo",
		"debug.trace",
		"env.PATH",
		"environ.HOME",
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			assert.Truef(t, IsForbidden(k), "expected %q to be forbidden", k)
		})
	}
}

func TestIsForbidden_AllowsContractKeys(t *testing.T) {
	cases := []string{
		"service.name",
		"service.version",
		"service.instance.id",
		"host.id",
		"host.name",
		"agent.id",
		"tenant.id",
		"security.scan.uid",
		"security.asset.uid",
		"security.finding.uid",
		"event.domain",
		"event.name",
		"security.asset.name",
		"security.finding.title",
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			assert.Falsef(t, IsForbidden(k), "expected %q to be allowed", k)
		})
	}
}

func TestIsForbidden_BlocksEmpty(t *testing.T) {
	assert.True(t, IsForbidden(""))
}

func TestFilter_RemovesForbiddenKeys(t *testing.T) {
	attrs := map[string]string{
		"service.name":       "kite-collector",
		"DB_PASSWORD":        "leaked",
		"api_key":            "leaked",
		"security.asset.uid": "12345",
	}
	got := Filter(attrs)
	assert.Equal(t, "kite-collector", got["service.name"])
	assert.Equal(t, "12345", got["security.asset.uid"])
	_, hasPwd := got["DB_PASSWORD"]
	_, hasKey := got["api_key"]
	assert.False(t, hasPwd, "password must be filtered")
	assert.False(t, hasKey, "api_key must be filtered")
}

func TestFilter_PassThroughWhenClean(t *testing.T) {
	attrs := map[string]string{
		"service.name":       "kite-collector",
		"event.name":         "asset.discovered",
		"security.asset.uid": "abc",
	}
	got := Filter(attrs)
	assert.Equal(t, len(attrs), len(got))
	assert.Equal(t, "kite-collector", got["service.name"])
}

func TestFilterKeys_RemovesForbidden(t *testing.T) {
	keys := []string{"service.name", "password", "tenant.id", "api_key"}
	got := FilterKeys(keys)
	assert.ElementsMatch(t, []string{"service.name", "tenant.id"}, got)
}
