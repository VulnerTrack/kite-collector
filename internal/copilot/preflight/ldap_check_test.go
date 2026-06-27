package preflight

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTCPListener spins up a localhost TCP listener so the DC-connect
// checker has something real to dial. The caller closes the listener
// when finished; the returned address is the host:port form. The
// listener uses (&net.ListenConfig{}).Listen to thread the test's
// context, satisfying the noctx linter.
func startTCPListener(t *testing.T) (string, func()) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestLDAPDCConnect_Empty(t *testing.T) {
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "discovery.ldap.domain_controllers", "", nil)
	assert.True(t, r.Passed)
}

func TestLDAPDCConnect_NilValue(t *testing.T) {
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "discovery.ldap.domain_controllers", nil, nil)
	assert.True(t, r.Passed)
	assert.Contains(t, r.Message, "no domain controllers")
}

func TestLDAPDCConnect_ReachableLocalhost(t *testing.T) {
	addr, cleanup := startTCPListener(t)
	defer cleanup()
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "dcs", addr, map[string]any{"discovery.ldap.tls_mode": "ldaps"})
	assert.True(t, r.Passed, "got: %+v", r)
	assert.Contains(t, r.Message, "1 domain controller")
}

func TestLDAPDCConnect_StringSliceReachable(t *testing.T) {
	addr, cleanup := startTCPListener(t)
	defer cleanup()
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "dcs", []string{addr}, nil)
	assert.True(t, r.Passed, "got: %+v", r)
}

func TestLDAPDCConnect_AnySliceReachable(t *testing.T) {
	addr, cleanup := startTCPListener(t)
	defer cleanup()
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "dcs", []any{addr}, nil)
	assert.True(t, r.Passed, "got: %+v", r)
}

func TestLDAPDCConnect_Unreachable(t *testing.T) {
	c := &LDAPDCConnectChecker{}
	// 192.0.2.0/24 is TEST-NET-1; guaranteed unroutable per RFC 5737.
	// Use a bogus high port to avoid colliding with anything local.
	r := c.Check(context.Background(), "dcs", "192.0.2.1:53999", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "cannot reach")
}

func TestLDAPDCConnect_InvalidEntry(t *testing.T) {
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "dcs", "host:notaport", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "invalid")
}

func TestLDAPDCConnect_MultipleAllReachable(t *testing.T) {
	addr1, c1 := startTCPListener(t)
	defer c1()
	addr2, c2 := startTCPListener(t)
	defer c2()
	c := &LDAPDCConnectChecker{}
	r := c.Check(context.Background(), "dcs", addr1+","+addr2, nil)
	assert.True(t, r.Passed, "got: %+v", r)
	assert.Contains(t, r.Message, "2 domain controller")
}

func TestLDAPDCConnect_FailsOnFirstUnreachable(t *testing.T) {
	addr, cleanup := startTCPListener(t)
	defer cleanup()
	c := &LDAPDCConnectChecker{}
	// Unreachable comes first → fail mentions that one.
	r := c.Check(context.Background(), "dcs", "192.0.2.1:53999,"+addr, nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "192.0.2.1")
}

func TestLDAPBindEnv_Empty(t *testing.T) {
	c := &LDAPBindEnvChecker{}
	r := c.Check(context.Background(), "n", "", nil)
	assert.True(t, r.Passed)
}

func TestLDAPBindEnv_Missing(t *testing.T) {
	c := &LDAPBindEnvChecker{}
	r := c.Check(context.Background(), "n", "KITE_LDAP_TEST_NEVER_SET_VAR", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "KITE_LDAP_TEST_NEVER_SET_VAR")
}

func TestLDAPBindEnv_Set(t *testing.T) {
	t.Setenv("KITE_LDAP_TEST_BIND_ENV_PRESENT", "secret")
	c := &LDAPBindEnvChecker{}
	r := c.Check(context.Background(), "n", "KITE_LDAP_TEST_BIND_ENV_PRESENT", nil)
	assert.True(t, r.Passed)
}

func TestLDAPBaseDN_Empty(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "", nil)
	assert.True(t, r.Passed)
}

func TestLDAPBaseDN_Valid(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "DC=corp,DC=acme,DC=com", nil)
	assert.True(t, r.Passed, "got %+v", r)
	assert.Contains(t, r.Message, "3 DC")
}

func TestLDAPBaseDN_ValidLowercase(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "dc=corp,dc=local", nil)
	assert.True(t, r.Passed)
}

func TestLDAPBaseDN_ValidWithOU(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "OU=Servers,DC=corp,DC=acme,DC=com", nil)
	assert.True(t, r.Passed, "got %+v", r)
}

func TestLDAPBaseDN_NoDC(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "OU=Workstations,CN=Computers", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, strings.ToLower(r.Message), "no dc")
}

func TestLDAPBaseDN_StrayComma(t *testing.T) {
	c := &LDAPBaseDNChecker{}
	r := c.Check(context.Background(), "n", "DC=corp,,DC=acme", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "empty component")
}

func TestLDAPTLSMode_Valid(t *testing.T) {
	c := &LDAPTLSModeChecker{}
	for _, mode := range []string{"ldaps", "starttls", "none"} {
		r := c.Check(context.Background(), "n", mode, nil)
		assert.True(t, r.Passed, "mode=%s should pass: %+v", mode, r)
	}
}

func TestLDAPTLSMode_Invalid(t *testing.T) {
	c := &LDAPTLSModeChecker{}
	for _, mode := range []string{"tls", "ssl", "ldap", "STARTTLS"} {
		r := c.Check(context.Background(), "n", mode, nil)
		assert.False(t, r.Passed, "mode=%s should fail", mode)
	}
}

func TestLDAPTLSMode_Empty(t *testing.T) {
	c := &LDAPTLSModeChecker{}
	r := c.Check(context.Background(), "n", "", nil)
	assert.True(t, r.Passed)
}

func TestDefaultLDAPPort(t *testing.T) {
	cases := map[string]int{
		"":         ldapPortLDAPS,
		"ldaps":    ldapPortLDAPS,
		"starttls": ldapPortPlain,
		"none":     ldapPortPlain,
	}
	for mode, want := range cases {
		got := defaultLDAPPort(map[string]any{"discovery.ldap.tls_mode": mode})
		assert.Equal(t, want, got, "mode=%s", mode)
	}
}

func TestParseHostPort(t *testing.T) {
	type want struct {
		host string
		port int
		err  bool
	}
	cases := map[string]want{
		"dc1.corp.acme.com":     {host: "dc1.corp.acme.com", port: 636},
		"dc1.corp.acme.com:389": {host: "dc1.corp.acme.com", port: 389},
		"dc1.corp.acme.com:":    {host: "dc1.corp.acme.com", port: 636},
		"":                      {err: true},
		"  ":                    {err: true},
		"host:99999":            {err: true},
		"host:abc":              {err: true},
		"[2001:db8::1]:636":     {host: "2001:db8::1", port: 636},
	}
	for in, w := range cases {
		host, port, err := parseHostPort(in, 636)
		if w.err {
			assert.Error(t, err, "input=%q", in)
			continue
		}
		require.NoError(t, err, "input=%q", in)
		assert.Equal(t, w.host, host, "input=%q", in)
		assert.Equal(t, w.port, port, "input=%q", in)
	}
}

func TestSplitDCList(t *testing.T) {
	cases := map[string]struct {
		in   any
		want []string
	}{
		"empty string":    {in: "", want: nil},
		"whitespace only": {in: "   ", want: nil},
		"single string":   {in: "dc1.corp", want: []string{"dc1.corp"}},
		"comma string":    {in: "dc1.corp, dc2.corp ", want: []string{"dc1.corp", "dc2.corp"}},
		"trailing comma":  {in: "dc1.corp,", want: []string{"dc1.corp"}},
		"string slice":    {in: []string{"dc1.corp", "  ", "dc2.corp"}, want: []string{"dc1.corp", "dc2.corp"}},
		"any slice":       {in: []any{"dc1.corp", 42, "dc2.corp"}, want: []string{"dc1.corp", "dc2.corp"}},
		"nil":             {in: nil, want: nil},
	}
	for name, tc := range cases {
		got := splitDCList(tc.in)
		assert.Equal(t, tc.want, got, "case=%s", name)
	}
}

// TestLDAPCheckersRegistered verifies the runner wires all four LDAP checkers.
func TestLDAPCheckersRegistered(t *testing.T) {
	r := NewRunner(2, nil)
	for _, tag := range []string{
		"ldap:dc:connect",
		"ldap:bind:env",
		"ldap:base_dn:syntax",
		"ldap:tls_mode:valid",
	} {
		_, ok := r.checkers[tag]
		assert.True(t, ok, "checker %q must be registered by NewRunner", tag)
	}
}
