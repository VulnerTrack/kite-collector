package vpn

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ciscoAnyConnectCollector reads Cisco AnyConnect / Secure Client
// "AnyConnectProfile" XML files. The client (renamed to "Cisco Secure
// Client" in 5.x) ships these XML profiles via the corporate ASA/FTD
// gateway after the first successful login; they list the gateways
// the client is allowed to connect to plus per-gateway settings
// (always-on, captive-portal handling, certificate auth requirements).
//
// XML schema (audit-relevant subset):
//
//	<AnyConnectProfile>
//	  <ClientInitialization>
//	    <AutoConnectOnStart>true</AutoConnectOnStart>
//	    <AlwaysOn>true</AlwaysOn>           ← always-on / full tunnel
//	    <CertificateStore>Login</CertificateStore>
//	  </ClientInitialization>
//	  <ServerList>
//	    <HostEntry>
//	      <HostName>vpn.example.com</HostName>
//	      <HostAddress>vpn.example.com</HostAddress>
//	      <PrimaryProtocol>SSL</PrimaryProtocol>
//	    </HostEntry>
//	    <HostEntry>…</HostEntry>
//	  </ServerList>
//	</AnyConnectProfile>
//
// Each <HostEntry> maps to one Profile. AlwaysOn ⇒ IsFullTunnel.
// PrimaryProtocol drives the Protocol field ("tls" for SSL, "ipsec"
// for IKEv2).
//
// Profiles live in well-known directories that vary by platform; the
// constructor accepts a slice so operators can extend it for custom
// MDM deployment paths.
type ciscoAnyConnectCollector struct {
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	profileDirs []string
}

// NewCiscoAnyConnectCollector returns the default AnyConnect collector
// that walks Linux, macOS and Windows-on-shared-volume profile paths.
func NewCiscoAnyConnectCollector() Collector {
	return &ciscoAnyConnectCollector{
		profileDirs: []string{
			// macOS
			"/opt/cisco/secureclient/vpn/profile",
			"/opt/cisco/anyconnect/profile",
			// Linux
			"/opt/cisco/secureclient/profile",
			"/etc/opt/cisco/anyconnect/profile",
			// Windows (when collector runs on a mounted volume)
			`C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile`,
			`C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile`,
		},
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *ciscoAnyConnectCollector) Name() string { return "cisco-anyconnect-profiles" }

// anyConnectProfile mirrors the AnyConnect XML subset we care about.
type anyConnectProfile struct {
	XMLName              xml.Name `xml:"AnyConnectProfile"`
	ClientInitialization struct {
		AutoConnectOnStart string `xml:"AutoConnectOnStart"`
		AlwaysOn           string `xml:"AlwaysOn"`
		CertificateStore   string `xml:"CertificateStore"`
	} `xml:"ClientInitialization"`
	ServerList struct {
		HostEntry []struct {
			HostName        string `xml:"HostName"`
			HostAddress     string `xml:"HostAddress"`
			PrimaryProtocol string `xml:"PrimaryProtocol"`
			UserGroup       string `xml:"UserGroup"`
		} `xml:"HostEntry"`
	} `xml:"ServerList"`
}

func (c *ciscoAnyConnectCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Profile
	for _, dir := range c.profileDirs {
		entries, err := c.readDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".xml") {
				continue
			}
			path := filepath.Join(dir, name)
			data, ferr := c.readFile(path)
			if ferr != nil {
				slog.Debug("vpn: anyconnect read failed", "path", path, "error", ferr)
				continue
			}
			hosts := parseAnyConnectProfile(data)
			for _, h := range hosts {
				h.ConfigPath = path
				out = append(out, h)
				if len(out) >= MaxProfiles {
					SortProfiles(out)
					return out, nil
				}
			}
		}
	}
	SortProfiles(out)
	return out, nil
}

// parseAnyConnectProfile decodes the XML and projects each
// <HostEntry> to a Profile. Returns nil for a malformed document.
func parseAnyConnectProfile(data []byte) []Profile {
	var doc anyConnectProfile
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	autoConnect := strings.EqualFold(doc.ClientInitialization.AutoConnectOnStart, "true")
	alwaysOn := strings.EqualFold(doc.ClientInitialization.AlwaysOn, "true")
	// CertificateStore is a stronger signal than absent — Login /
	// Machine both imply a cert lives somewhere on disk.
	hasCertPath := strings.TrimSpace(doc.ClientInitialization.CertificateStore) != ""

	out := make([]Profile, 0, len(doc.ServerList.HostEntry))
	for _, h := range doc.ServerList.HostEntry {
		proto := "tls"
		if strings.EqualFold(h.PrimaryProtocol, "IPsec") || strings.EqualFold(h.PrimaryProtocol, "ipsec") {
			proto = "ipsec"
		}
		endpoint := strings.TrimSpace(h.HostAddress)
		if endpoint == "" {
			endpoint = strings.TrimSpace(h.HostName)
		}
		name := strings.TrimSpace(h.HostName)
		if name == "" {
			name = endpoint
		}
		if name == "" {
			continue
		}
		p := Profile{
			Type:              TypeCiscoAnyConnect,
			Name:              name,
			Endpoint:          endpoint,
			Protocol:          proto,
			Enabled:           true,
			AutoConnect:       autoConnect,
			PrivateKeyPresent: hasCertPath,
			IsFullTunnel:      alwaysOn,
		}
		// AlwaysOn redirects all traffic through the gateway →
		// synthesize default routes so the CWE-200 query catches it.
		if alwaysOn {
			p.RoutedSubnets = []string{"0.0.0.0/0", "::/0"}
		}
		out = append(out, p)
	}
	return out
}
