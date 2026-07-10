package vpn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const anyConnectProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ClientInitialization>
    <AutoConnectOnStart>true</AutoConnectOnStart>
    <AlwaysOn>true</AlwaysOn>
    <CertificateStore>Login</CertificateStore>
  </ClientInitialization>
  <ServerList>
    <HostEntry>
      <HostName>HQ</HostName>
      <HostAddress>vpn.example.com</HostAddress>
      <PrimaryProtocol>SSL</PrimaryProtocol>
    </HostEntry>
    <HostEntry>
      <HostName>DR-Site</HostName>
      <HostAddress>vpn-dr.example.com</HostAddress>
      <PrimaryProtocol>IPsec</PrimaryProtocol>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`

func TestParseAnyConnectProfileAlwaysOn(t *testing.T) {
	got := parseAnyConnectProfile([]byte(anyConnectProfileXML))
	if len(got) != 2 {
		t.Fatalf("want 2 host entries, got %d", len(got))
	}
	for _, p := range got {
		if p.Type != TypeCiscoAnyConnect {
			t.Fatalf("type=%q", p.Type)
		}
		if !p.IsFullTunnel {
			t.Fatal("AlwaysOn=true must flag IsFullTunnel")
		}
		if !p.AutoConnect {
			t.Fatal("AutoConnectOnStart=true must flag AutoConnect")
		}
		if !p.PrivateKeyPresent {
			t.Fatal("CertificateStore set ⇒ PrivateKeyPresent")
		}
		if !contains(p.RoutedSubnets, "0.0.0.0/0") {
			t.Fatalf("AlwaysOn must synthesize default route, got %v", p.RoutedSubnets)
		}
	}
	if got[0].Protocol != "tls" {
		t.Fatalf("SSL → tls, got %q", got[0].Protocol)
	}
	if got[1].Protocol != "ipsec" {
		t.Fatalf("IPsec → ipsec, got %q", got[1].Protocol)
	}
}

func TestParseAnyConnectMalformedReturnsNil(t *testing.T) {
	if got := parseAnyConnectProfile([]byte("<not-xml")); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestCiscoAnyConnectCollectorWalksDir(t *testing.T) {
	tmp := t.TempDir()
	mustWrite(t, filepath.Join(tmp, "corp.xml"), anyConnectProfileXML)
	mustWrite(t, filepath.Join(tmp, "README"), "skip")

	c := &ciscoAnyConnectCollector{
		profileDirs: []string{tmp, "/never/exists"},
		readFile:    os.ReadFile,
		readDir:     func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 profiles (one per HostEntry), got %d", len(got))
	}
	for _, p := range got {
		if p.ConfigPath != filepath.Join(tmp, "corp.xml") {
			t.Fatalf("config_path=%q", p.ConfigPath)
		}
	}
}

func TestCiscoAnyConnectMissingDirReturnsEmpty(t *testing.T) {
	c := &ciscoAnyConnectCollector{
		profileDirs: []string{"/does/not/exist"},
		readDir:     func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}
