package vpn

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// openvpnEnumerator discovers the clients CONNECTED to OpenVPN servers on
// this host by parsing their status files. Each client is a remote host,
// and — uniquely among the fabrics here — OpenVPN reports the authenticated
// username, so the owning user is captured directly.
//
// Status-file locations vary by distro/config; a curated candidate list is
// probed and can be overridden with KITE_OPENVPN_STATUS_FILES (a
// comma-separated list of absolute paths). A file that is missing or
// unreadable (the status files are commonly root-only) is skipped, never
// fatal.
type openvpnEnumerator struct {
	readFile fileReader
	getenv   func(string) string
	defaults []string
}

func newOpenVPNEnumerator() *openvpnEnumerator {
	return &openvpnEnumerator{
		readFile: osReadFile,
		getenv:   defaultGetenv,
		defaults: []string{
			"/etc/openvpn/server/openvpn-status.log",
			"/etc/openvpn/openvpn-status.log",
			"/var/log/openvpn/status.log",
			"/var/log/openvpn-status.log",
			"/run/openvpn-server/status-server.log",
		},
	}
}

func (e *openvpnEnumerator) vpnType() string { return "openvpn" }

func (e *openvpnEnumerator) enumerate(_ context.Context, _ map[string]any) ([]Peer, error) {
	paths := e.defaults
	if override := strings.TrimSpace(e.getenv("KITE_OPENVPN_STATUS_FILES")); override != "" {
		paths = splitAndTrim(override, ',')
	}

	var out []Peer
	for _, path := range paths {
		data, err := e.readFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				// Permission denied on a root-only status file is expected
				// when the collector runs unprivileged — record it but do
				// not fail the fabric.
				slog.Debug("vpn: openvpn status read failed",
					"code", string(LogCodeOpenVPNStatusReadFailed),
					"path", path, "error", err)
			}
			continue
		}
		out = append(out, parseOpenVPNStatus(string(data))...)
	}
	return out, nil
}

// parseOpenVPNStatus dispatches on the status-file format. Versions 2 and 3
// are line-prefixed and machine-readable (comma- or tab-separated); version
// 1 is a sectioned CSV. Both are handled.
func parseOpenVPNStatus(raw string) []Peer {
	if strings.Contains(raw, "CLIENT_LIST") {
		return parseOpenVPNMachine(raw)
	}
	return parseOpenVPNV1(raw)
}

// parseOpenVPNMachine handles status-version 2 (comma) and 3 (tab). The
// CLIENT_LIST column order is fixed by OpenVPN:
//
//	CLIENT_LIST, Common Name, Real Address, Virtual Address, Virtual IPv6,
//	  Bytes Received, Bytes Sent, Connected Since, Connected Since (time_t),
//	  Username, Client ID, Peer ID, Data Channel Cipher
func parseOpenVPNMachine(raw string) []Peer {
	var out []Peer
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			continue
		}
		sep := byte(',')
		if strings.Contains(line, "\t") {
			sep = '\t'
		}
		f := splitAndTrim(line, sep)
		if len(f) < 4 {
			continue
		}
		cn := field(f, 1)
		real := field(f, 2)
		vaddr := field(f, 3)
		username := field(f, 9)
		var lastSeen time.Time
		if epoch := field(f, 8); epoch != "" {
			if n, err := strconv.ParseInt(epoch, 10, 64); err == nil && n > 0 {
				lastSeen = time.Unix(n, 0).UTC()
			}
		}
		out = append(out, openvpnPeer(cn, username, real, vaddr, lastSeen))
	}
	return out
}

// parseOpenVPNV1 handles the default human-readable status file. The
// "CLIENT LIST" section rows are: Common Name, Real Address, Bytes Received,
// Bytes Sent, Connected Since. The "ROUTING TABLE" maps Virtual Address to
// Common Name, which we join back to fill the overlay address.
func parseOpenVPNV1(raw string) []Peer {
	type row struct {
		cn, real, since string
	}
	var clients []row
	vaddrByCN := map[string]string{}

	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		switch {
		case t == "OpenVPN CLIENT LIST" || strings.HasPrefix(t, "Common Name,Real Address"):
			section = "clients"
			continue
		case t == "ROUTING TABLE" || strings.HasPrefix(t, "Virtual Address,Common Name"):
			section = "routing"
			continue
		case t == "GLOBAL STATS" || t == "END" || strings.HasPrefix(t, "Updated,") || strings.HasPrefix(t, "Max bcast"):
			section = ""
			continue
		}
		f := splitAndTrim(t, ',')
		switch section {
		case "clients":
			if len(f) >= 5 {
				clients = append(clients, row{cn: f[0], real: f[1], since: f[4]})
			}
		case "routing":
			if len(f) >= 2 {
				vaddrByCN[f[1]] = f[0]
			}
		}
	}

	out := make([]Peer, 0, len(clients))
	for _, c := range clients {
		out = append(out, openvpnPeer(c.cn, "", c.real, vaddrByCN[c.cn], parseOpenVPNDate(c.since)))
	}
	return out
}

// openvpnPeer builds a Peer from the common OpenVPN client fields. A client
// present in the status file is by definition currently connected.
func openvpnPeer(cn, username, real, vaddr string, lastSeen time.Time) Peer {
	owner := username
	if owner == "" && cn != "" && !strings.EqualFold(cn, "UNDEF") {
		owner = cn
	}
	hostname := cn
	if hostname == "" || strings.EqualFold(hostname, "UNDEF") {
		hostname = vaddr
	}
	p := Peer{
		VPNType:  "openvpn",
		Hostname: hostname,
		Owner:    owner,
		Endpoint: real,
		Online:   true,
		LastSeen: lastSeen,
		Tags:     map[string]any{},
	}
	if vaddr != "" {
		p.Addresses = sortAddrs([]string{vaddr})
	}
	if cn != "" {
		p.Tags["common_name"] = cn
	}
	if username != "" {
		p.Tags["username"] = username
	}
	return p
}

// parseOpenVPNDate parses the v1 "Connected Since" local timestamp
// ("2026-08-19 11:00:00"). Timezone is unspecified in the file, so it is
// read as UTC; failure yields the zero time (mapper substitutes scan time).
func parseOpenVPNDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "Mon Jan  2 15:04:05 2006", "Mon Jan 2 15:04:05 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// splitAndTrim splits on sep and trims each field.
func splitAndTrim(s string, sep byte) []string {
	parts := strings.Split(s, string(sep))
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// field safely returns the i-th element or "".
func field(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}
