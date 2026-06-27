package mongodconf

import (
	"context"
	"errors"
	"io/fs"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceConfigYAML), "config-yaml"},
		{string(SourceNoConfig), "no-config"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("net:\n  port: 27017\n"))
	b := HashContents([]byte("net:\n  port: 27017\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	hit := []string{"127.0.0.1", "::1", "localhost", "127.0.0.2"}
	for _, a := range hit {
		if !IsLoopbackAddress(a) {
			t.Fatalf("%q must flag loopback", a)
		}
	}
	miss := []string{"0.0.0.0", "::", "10.0.0.5", "192.168.1.1", "fe80::1", ""}
	for _, a := range miss {
		if IsLoopbackAddress(a) {
			t.Fatalf("%q must NOT flag loopback", a)
		}
	}
}

func TestIsExternalBindListCoversUnset(t *testing.T) {
	if !IsExternalBindList(nil) {
		t.Fatal("empty bindIp = listen everywhere = external")
	}
	if !IsExternalBindList([]string{"127.0.0.1", "10.0.0.5"}) {
		t.Fatal("mixed must flag external")
	}
	if IsExternalBindList([]string{"127.0.0.1", "::1"}) {
		t.Fatal("loopback-only must NOT flag external")
	}
}

func TestIsLoopbackOnlyList(t *testing.T) {
	if !IsLoopbackOnlyList([]string{"127.0.0.1", "::1"}) {
		t.Fatal("all-loopback must flag")
	}
	if IsLoopbackOnlyList([]string{"127.0.0.1", "10.0.0.5"}) {
		t.Fatal("mixed must NOT flag loopback-only")
	}
	if IsLoopbackOnlyList(nil) {
		t.Fatal("empty (= listen all) must NOT flag loopback-only")
	}
}

func TestTLSModeIsEnabled(t *testing.T) {
	for _, m := range []string{"allowTLS", "preferTLS", "requireTLS", "REQUIRETLS"} {
		if !TLSModeIsEnabled(m) {
			t.Fatalf("%q must flag enabled", m)
		}
	}
	for _, m := range []string{"", "disabled", "DISABLED", " disabled "} {
		if TLSModeIsEnabled(m) {
			t.Fatalf("%q must NOT flag enabled", m)
		}
	}
}

func TestIsHardenedRequiresAllKnobs(t *testing.T) {
	base := State{
		BindIPs:           []string{"127.0.0.1"},
		AuthorizationMode: "enabled",
		TLSMode:           "requireTLS",
		// Explicit javascriptEnabled=false applies because annotate
		// won't override IsScriptingEnabled.
	}
	AnnotateSecurity(&base)
	if !base.IsHardened {
		t.Fatalf("baseline must be hardened: %+v", base)
	}

	// Flip auth → un-harden.
	bad := base
	bad.IsAuthorizationDisabled = true
	AnnotateSecurity(&bad)
	if bad.IsHardened {
		t.Fatal("auth disabled must un-harden")
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"127.0.0.1"}); got != `["127.0.0.1"]` {
		t.Fatalf("got %q", got)
	}
}

// -- ParseConfig typical hardened -----------------------------------

func TestParseConfigTypicalHardened(t *testing.T) {
	body := []byte(`
net:
  port: 27017
  bindIp: 127.0.0.1,::1
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongo.pem
security:
  authorization: enabled
  javascriptEnabled: false
  keyFile: /etc/mongo.keyfile
storage:
  dbPath: /var/lib/mongo
systemLog:
  destination: file
  path: /var/log/mongod.log
replication:
  replSetName: rs0
`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	AnnotateSecurity(&got)
	if got.Port != 27017 {
		t.Fatalf("port=%d", got.Port)
	}
	if len(got.BindIPs) != 2 {
		t.Fatalf("bindIPs=%v", got.BindIPs)
	}
	if !got.IsBoundToLoopbackOnly {
		t.Fatal("loopback-only must flag")
	}
	if got.IsExternallyBound {
		t.Fatal("loopback-only must NOT flag external")
	}
	if got.IsAuthorizationDisabled {
		t.Fatal("authorization: enabled must propagate")
	}
	if got.IsScriptingEnabled {
		t.Fatal("javascriptEnabled: false must propagate")
	}
	if !got.IsTLSEnabled {
		t.Fatal("requireTLS must flag enabled")
	}
	if got.IsTLSDisabledWithExternalBind {
		t.Fatal("loopback-only must NOT flag plaintext-external")
	}
	if got.IsUnauthenticatedWorldExposed {
		t.Fatal("hardened must NOT flag world-exposed")
	}
	if !got.IsHardened {
		t.Fatalf("rolled-up IsHardened must be true: %+v", got)
	}
}

// -- ParseConfig worst-case -----------------------------------------

func TestParseConfigWorstCase(t *testing.T) {
	body := []byte(`
net:
  port: 27017
  bindIpAll: true
security:
  authorization: disabled
`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	AnnotateSecurity(&got)
	if !got.IsExternallyBound {
		t.Fatal("bindIpAll=true must flag external")
	}
	if !got.IsAuthorizationDisabled {
		t.Fatal("authorization: disabled must propagate")
	}
	if !got.IsScriptingEnabled {
		t.Fatal("javascriptEnabled default = true must propagate")
	}
	if !got.IsUnauthenticatedWorldExposed {
		t.Fatalf("worst-case must flag world-exposed: %+v", got)
	}
	if !got.IsTLSDisabledWithExternalBind {
		t.Fatal("no TLS + external bind must flag")
	}
	if got.IsHardened {
		t.Fatal("worst-case must NOT be hardened")
	}
}

// -- ParseConfig empty / missing-auth-key handling -------------------

func TestParseConfigUnsetAuthDefaultsToDisabled(t *testing.T) {
	// MongoDB's documented default: omit security.authorization →
	// treated as disabled.
	body := []byte(`
net:
  port: 27017
  bindIp: 127.0.0.1
`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsAuthorizationDisabled {
		t.Fatal("missing authorization key must default to disabled")
	}
	if !got.IsScriptingEnabled {
		t.Fatal("missing javascriptEnabled must default to true")
	}
	AnnotateSecurity(&got)
	if got.IsUnauthenticatedWorldExposed {
		t.Fatal("loopback bind must clear world-exposed even with auth disabled")
	}
}

// -- ParseConfig localhost-auth-bypass via setParameter --------------

func TestParseConfigLocalhostAuthBypassDetection(t *testing.T) {
	body := []byte(`
security:
  authorization: enabled
setParameter:
  enableLocalhostAuthBypass: true
`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsLocalhostAuthBypassEnabled {
		t.Fatal("setParameter.enableLocalhostAuthBypass=true must propagate")
	}
}

// -- ParseConfig bindIp comma-separated handling ---------------------

func TestParseConfigBindIPCommaSeparated(t *testing.T) {
	body := []byte(`
net:
  bindIp: "127.0.0.1, ::1 , 10.0.0.5"
`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BindIPs) != 3 {
		t.Fatalf("bindIPs=%v", got.BindIPs)
	}
	AnnotateSecurity(&got)
	if !got.IsExternallyBound {
		t.Fatal("mixed bind list with non-loopback must flag external")
	}
}

// -- ParseConfig BOM tolerance --------------------------------------

func TestParseConfigStripsBOM(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte("net:\n  port: 27017\n")...)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.Port != 27017 {
		t.Fatalf("port=%d", got.Port)
	}
}

// -- error paths ----------------------------------------------------

func TestParseConfigEmpty(t *testing.T) {
	if _, err := ParseConfig(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseConfigMalformed(t *testing.T) {
	if _, err := ParseConfig([]byte(":\n  - [bogus\n")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorPicksFirstReadable(t *testing.T) {
	body := []byte(`
net:
  bindIp: 0.0.0.0
security:
  authorization: disabled
`)
	c := &fileCollector{
		paths: []string{"/none-a", "/etc/mongod.conf"},
		readFile: func(p string) ([]byte, error) {
			if p == "/none-a" {
				return nil, fs.ErrNotExist
			}
			return body, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.Source != SourceConfigYAML {
		t.Fatalf("source=%q", got.Source)
	}
	if got.ConfigPath != "/etc/mongod.conf" {
		t.Fatalf("config_path=%q", got.ConfigPath)
	}
	if got.FileHash == "" {
		t.Fatal("file_hash missing")
	}
	if !got.IsUnauthenticatedWorldExposed {
		t.Fatalf("flags wrong: %+v", got)
	}
}

func TestFileCollectorAllMissingReturnsNoConfig(t *testing.T) {
	c := &fileCollector{
		paths: []string{"/none-a", "/none-b"},
		readFile: func(string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if got.Source != SourceNoConfig {
		t.Fatalf("source=%q want no-config", got.Source)
	}
}

func TestFileCollectorReadErrorPropagates(t *testing.T) {
	boom := errors.New("io boom")
	c := &fileCollector{
		paths: []string{"/x"},
		readFile: func(string) ([]byte, error) {
			return nil, boom
		},
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("read error must propagate")
	}
	if got.Source != SourceUnknown {
		t.Fatalf("source=%q want unknown", got.Source)
	}
}

func TestFileCollectorMalformedFile(t *testing.T) {
	c := &fileCollector{
		paths: []string{"/x"},
		readFile: func(string) ([]byte, error) {
			return []byte(":\n  - [bogus\n"), nil
		},
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("malformed must error")
	}
	if got.Source != SourceUnknown {
		t.Fatalf("source=%q want unknown", got.Source)
	}
	if got.ConfigPath != "/x" {
		t.Fatalf("path missing: %q", got.ConfigPath)
	}
}

// -- SortBindIPs ----------------------------------------------------

func TestSortBindIPsDeterministic(t *testing.T) {
	s := State{BindIPs: []string{"::1", "127.0.0.1", "10.0.0.5"}}
	SortBindIPs(&s)
	if s.BindIPs[0] != "10.0.0.5" {
		t.Fatalf("first=%q", s.BindIPs[0])
	}
}
