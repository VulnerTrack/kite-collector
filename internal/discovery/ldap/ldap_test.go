package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// fakeConn implements directoryConn for the unit tests. It records calls
// and serves a canned SearchWithPaging result.
type fakeConn struct {
	bindDN      string
	bindPwd     string
	bindErr     error
	startTLSErr error
	searchErr   error
	result      *ldapv3.SearchResult
	closed      bool
	startTLSed  bool
}

func (c *fakeConn) Bind(dn, pwd string) error {
	c.bindDN, c.bindPwd = dn, pwd
	return c.bindErr
}
func (c *fakeConn) StartTLS(*tls.Config) error { c.startTLSed = true; return c.startTLSErr }
func (c *fakeConn) SearchWithPaging(_ *ldapv3.SearchRequest, _ uint32) (*ldapv3.SearchResult, error) {
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	if c.result == nil {
		return &ldapv3.SearchResult{}, nil
	}
	return c.result, nil
}
func (c *fakeConn) Close() error { c.closed = true; return nil }

func newComputerEntry(dn string, attrs map[string][]string, raw map[string][]byte) *ldapv3.Entry {
	e := &ldapv3.Entry{DN: dn}
	for name, values := range attrs {
		e.Attributes = append(e.Attributes, &ldapv3.EntryAttribute{Name: name, Values: values})
	}
	for name, value := range raw {
		// go-ldap matches GetRawAttributeValue against the same attribute
		// name; storing the raw bytes in ByteValues is sufficient.
		e.Attributes = append(e.Attributes, &ldapv3.EntryAttribute{
			Name:       name,
			ByteValues: [][]byte{value},
		})
	}
	return e
}

func TestLDAP_Name(t *testing.T) {
	if got := New().Name(); got != "ldap" {
		t.Errorf("Name() = %q, want %q", got, "ldap")
	}
}

func TestLDAP_Discover_Disabled(t *testing.T) {
	src := &LDAP{
		dial: func(context.Context, *ldapConfig, dcEndpoint) (directoryConn, error) {
			t.Fatal("dial must not be called when source is disabled")
			return nil, nil
		},
		now: time.Now,
	}
	got, err := src.Discover(context.Background(), map[string]any{"enabled": false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled source returned %d assets", len(got))
	}
}

func TestLDAP_Discover_AllDCsFail(t *testing.T) {
	src := &LDAP{
		dial: func(context.Context, *ldapConfig, dcEndpoint) (directoryConn, error) {
			return nil, errors.New("dial refused")
		},
		now: time.Now,
	}
	t.Setenv("KITE_LDAP_BIND_PASSWORD", "secret")
	cfg := map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,OU=Users,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com", "dc2.corp.acme.com"},
	}
	_, err := src.Discover(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when all DCs fail")
	}
	if !strings.Contains(err.Error(), "all domain controllers failed") {
		t.Errorf("error %q missing the all-DCs-failed phrase", err)
	}
}

func TestLDAP_Discover_HappyPath(t *testing.T) {
	conn := &fakeConn{
		result: &ldapv3.SearchResult{
			Entries: []*ldapv3.Entry{
				newComputerEntry(
					"CN=WS01,OU=Workstations,DC=corp,DC=acme,DC=com",
					map[string][]string{
						"sAMAccountName":         {"WS01$"},
						"dnsHostName":            {"ws01.corp.acme.com"},
						"operatingSystem":        {"Windows 11 Enterprise"},
						"operatingSystemVersion": {"10.0 (22631)"},
						"userAccountControl":     {"4096"}, // workstation trust, enabled
						"lastLogonTimestamp":     {"133612344000000000"},
						"pwdLastSet":             {"133600000000000000"},
					},
					map[string][]byte{
						"objectSid": {
							0x01, 0x05,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
							0x15, 0x00, 0x00, 0x00,
							0x01, 0x00, 0x00, 0x00,
							0x02, 0x00, 0x00, 0x00,
							0x03, 0x00, 0x00, 0x00,
							0xe9, 0x03, 0x00, 0x00,
						},
					},
				),
			},
		},
	}
	src := &LDAP{
		dial: func(context.Context, *ldapConfig, dcEndpoint) (directoryConn, error) { return conn, nil },
		now:  func() time.Time { return time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC) },
	}
	t.Setenv("KITE_LDAP_BIND_PASSWORD", "secret")

	cfg := map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,OU=Users,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
	}
	assets, err := src.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	a := assets[0]
	if a.Hostname != "ws01.corp.acme.com" {
		t.Errorf("hostname = %q, want %q", a.Hostname, "ws01.corp.acme.com")
	}
	if a.DiscoverySource != SourceName {
		t.Errorf("source = %q, want %q", a.DiscoverySource, SourceName)
	}
	if !conn.closed {
		t.Error("connection was not closed")
	}
	if conn.bindDN != "CN=svc,OU=Users,DC=corp,DC=acme,DC=com" {
		t.Errorf("bindDN = %q", conn.bindDN)
	}
}

func TestLDAP_Discover_BindFailureSurfaces(t *testing.T) {
	conn := &fakeConn{bindErr: errors.New("invalid creds")}
	src := &LDAP{
		dial: func(context.Context, *ldapConfig, dcEndpoint) (directoryConn, error) { return conn, nil },
		now:  time.Now,
	}
	t.Setenv("KITE_LDAP_BIND_PASSWORD", "secret")
	cfg := map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
	}
	if _, err := src.Discover(context.Background(), cfg); err == nil {
		t.Fatal("expected bind error to surface")
	}
}

func TestLDAP_Discover_MissingPassword(t *testing.T) {
	src := New()
	t.Setenv("KITE_LDAP_BIND_PASSWORD", "")
	cfg := map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
	}
	_, err := src.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "KITE_LDAP_BIND_PASSWORD") {
		t.Fatalf("expected missing-password error, got %v", err)
	}
}

func TestLDAP_Discover_MaxObjectsTrips(t *testing.T) {
	entries := make([]*ldapv3.Entry, 5)
	for i := range entries {
		entries[i] = newComputerEntry(
			"CN=H,DC=corp,DC=acme,DC=com",
			map[string][]string{
				"sAMAccountName":     {"H$"},
				"dnsHostName":        {"h.corp.acme.com"},
				"operatingSystem":    {"Windows Server"},
				"userAccountControl": {"8192"}, // SERVER_TRUST
			},
			nil,
		)
	}
	conn := &fakeConn{result: &ldapv3.SearchResult{Entries: entries}}
	src := &LDAP{
		dial: func(context.Context, *ldapConfig, dcEndpoint) (directoryConn, error) { return conn, nil },
		now:  time.Now,
	}
	t.Setenv("KITE_LDAP_BIND_PASSWORD", "secret")
	cfg := map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
		"max_objects":        2,
	}
	assets, err := src.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("max_objects=2 should have truncated, got %d", len(assets))
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	c, err := parseConfig(map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.tlsMode != "ldaps" {
		t.Errorf("tlsMode = %q", c.tlsMode)
	}
	if c.pageSize != 1000 {
		t.Errorf("pageSize = %d", c.pageSize)
	}
	if c.timeoutSeconds != 300 {
		t.Errorf("timeoutSeconds = %d", c.timeoutSeconds)
	}
	if c.staleThresholdDays != 90 {
		t.Errorf("staleThresholdDays = %d", c.staleThresholdDays)
	}
	if len(c.domainControllers) != 1 || c.domainControllers[0].port != 636 {
		t.Errorf("domain_controllers = %+v", c.domainControllers)
	}
}

func TestParseConfig_RejectsBadTLSMode(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"enabled":  true,
		"tls_mode": "weird",
		"base_dn":  "DC=corp,DC=acme,DC=com",
		"bind_dn":  "CN=svc",
		"domain_controllers": []any{"dc"},
	})
	if err == nil {
		t.Fatal("expected error for bad tls_mode")
	}
}

func TestParseConfig_StarttlsDefaultPort(t *testing.T) {
	c, err := parseConfig(map[string]any{
		"enabled":            true,
		"tls_mode":           "starttls",
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com"},
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.domainControllers[0].port != 389 {
		t.Errorf("starttls default port = %d, want 389", c.domainControllers[0].port)
	}
}

func TestParseConfig_HostPortString(t *testing.T) {
	c, err := parseConfig(map[string]any{
		"enabled":            true,
		"base_dn":            "DC=corp,DC=acme,DC=com",
		"bind_dn":            "CN=svc,DC=corp,DC=acme,DC=com",
		"domain_controllers": []any{"dc1.corp.acme.com:3269"},
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.domainControllers[0].host != "dc1.corp.acme.com" || c.domainControllers[0].port != 3269 {
		t.Errorf("dc parse = %+v", c.domainControllers[0])
	}
}

func TestParseObjectSID(t *testing.T) {
	// S-1-5-21-1-2-3-1001
	raw := []byte{
		0x01, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x15, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00,
		0xe9, 0x03, 0x00, 0x00,
	}
	got := parseObjectSID(raw)
	want := "S-1-5-21-1-2-3-1001"
	if got != want {
		t.Errorf("parseObjectSID = %q, want %q", got, want)
	}
}

func TestParseObjectSID_Malformed(t *testing.T) {
	if got := parseObjectSID([]byte{0x01}); got != "" {
		t.Errorf("malformed SID returned %q, want empty", got)
	}
	if got := parseObjectSID(nil); got != "" {
		t.Errorf("nil SID returned %q, want empty", got)
	}
}

func TestWindowsTimeToUnix(t *testing.T) {
	cases := map[string]struct {
		in   int64
		want int64
	}{
		"zero":       {0, 0},
		"never":      {0x7FFFFFFFFFFFFFFF, 0},
		"unix_epoch": {116444736000000000, 0},
		"y2024":      {133612344000000000, 1716760800},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := windowsTimeToUnix(tc.in); got != tc.want {
				t.Errorf("windowsTimeToUnix(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractComputer(t *testing.T) {
	e := newComputerEntry(
		"CN=DC1,OU=Domain Controllers,DC=corp,DC=acme,DC=com",
		map[string][]string{
			"sAMAccountName":         {"DC1$"},
			"dnsHostName":            {"dc1.corp.acme.com"},
			"operatingSystem":        {"Windows Server 2022"},
			"operatingSystemVersion": {"10.0 (20348)"},
			"userAccountControl":     {"532480"}, // SERVER_TRUST | TRUSTED_FOR_DELEG
			"servicePrincipalName":   {"HOST/dc1", "HOST/dc1.corp.acme.com"},
			"memberOf":               {"CN=Domain Controllers,DC=corp,DC=acme,DC=com"},
		},
		nil,
	)
	c, err := extractComputer(e, "DC=corp,DC=acme,DC=com")
	if err != nil {
		t.Fatalf("extractComputer: %v", err)
	}
	if c.samAccountName != "DC1" {
		t.Errorf("samAccountName = %q, want DC1", c.samAccountName)
	}
	if c.domainDNSName != "corp.acme.com" {
		t.Errorf("domainDNSName = %q", c.domainDNSName)
	}
	if c.ouPath != "OU=Domain Controllers,DC=corp,DC=acme,DC=com" {
		t.Errorf("ouPath = %q", c.ouPath)
	}
	if !c.enabled {
		t.Error("DC should be enabled")
	}
	if len(c.servicePrincipals) != 2 {
		t.Errorf("SPNs = %v", c.servicePrincipals)
	}
}

func TestExtractComputer_DisabledAccount(t *testing.T) {
	e := newComputerEntry("CN=OLD,DC=corp,DC=acme,DC=com",
		map[string][]string{
			"sAMAccountName":     {"OLD$"},
			"userAccountControl": {"4098"}, // workstation + disabled
		},
		nil,
	)
	c, err := extractComputer(e, "DC=corp,DC=acme,DC=com")
	if err != nil {
		t.Fatalf("extractComputer: %v", err)
	}
	if c.enabled {
		t.Error("UAC bit 2 set: account should be disabled")
	}
}

func TestClassifyAsset(t *testing.T) {
	if classifyAsset(uacWorkstation, "Windows 11") != "workstation" {
		t.Error("workstation trust should classify as workstation")
	}
	if classifyAsset(uacServerTrust, "Windows Server") != "server" {
		t.Error("server trust should classify as server")
	}
	if classifyAsset(0, "Windows Server 2022") != "server" {
		t.Error("operatingSystem fallback to server")
	}
}

func TestDomainFromBaseDN(t *testing.T) {
	if got := domainFromBaseDN("DC=corp,DC=acme,DC=com"); got != "corp.acme.com" {
		t.Errorf("got %q", got)
	}
	if got := domainFromBaseDN("OU=foo"); got != "" {
		t.Errorf("non-DC base returned %q", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		dPort    int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"dc1.corp.acme.com", 636, "dc1.corp.acme.com", 636, false},
		{"dc1.corp.acme.com:3269", 636, "dc1.corp.acme.com", 3269, false},
		{"[::1]:636", 636, "::1", 636, false},
		{"", 636, "", 0, true},
		{"dc:bad", 636, "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitHostPort(tc.in, tc.dPort)
		if tc.wantErr != (err != nil) {
			t.Errorf("splitHostPort(%q): err = %v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}
