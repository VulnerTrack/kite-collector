package dnsresolver

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseResolvConf walks an /etc/resolv.conf file body. Grammar per
// resolv.conf(5):
//
//	nameserver <IP>
//	search    <domain> [<domain>...]
//	domain    <domain>          (legacy; alias for search)
//	options   ndots:N rotate ... (parsed only to flag DNSSEC if present)
//
// Each `nameserver` line yields one Resolver row; `search` and
// `domain` populate every row's SearchDomains.
func ParseResolvConf(raw []byte, filePath string) []Resolver {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		servers []serverLine
		search  []string
		dnssec  bool
	)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			servers = append(servers, serverLine{
				server:  fields[1],
				lineNo:  i + 1,
				rawLine: clean,
			})
		case "search":
			search = append(search, fields[1:]...)
		case "domain":
			// `domain` is a single-domain alias for `search`.
			search = append(search, fields[1])
		case "options":
			for _, opt := range fields[1:] {
				if strings.EqualFold(opt, "edns0") ||
					strings.EqualFold(opt, "trust-ad") {
					dnssec = true
				}
			}
		}
	}

	out := make([]Resolver, 0, len(servers))
	for _, s := range servers {
		r := Resolver{
			Source:        SourceResolvConf,
			Scope:         ScopeSystem,
			Server:        s.server,
			Port:          53,
			Protocol:      ProtocolUDP,
			SearchDomains: append([]string(nil), search...),
			IsDNSSEC:      dnssec,
			FilePath:      filePath,
			FileHash:      hash,
			LineNo:        s.lineNo,
			RawLine:       s.rawLine,
		}
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxResolvers {
			break
		}
	}
	return out
}

type serverLine struct {
	server  string
	rawLine string
	lineNo  int
}

// ParseSystemdResolvedConf walks /etc/systemd/resolved.conf or a drop-in
// under /etc/systemd/resolved.conf.d/. Grammar per resolved.conf(5):
//
//	[Resolve]
//	DNS=1.1.1.1 8.8.8.8
//	FallbackDNS=...
//	Domains=~corp.local
//	DNSSEC=yes
//	DNSOverTLS=opportunistic
//
// We emit one Resolver per DNS=/FallbackDNS= server token.
func ParseSystemdResolvedConf(raw []byte, filePath string) []Resolver {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		section  string
		servers  []string
		domains  []string
		dnssec   bool
		protocol = ProtocolUDP
		fallback []string
	)
	for _, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		// INI section headers.
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			section = strings.ToLower(strings.Trim(clean, "[]"))
			continue
		}
		if section != "resolve" {
			continue
		}
		key, value, ok := splitKV(clean)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "dns":
			servers = append(servers, strings.Fields(value)...)
		case "fallbackdns":
			fallback = append(fallback, strings.Fields(value)...)
		case "domains":
			domains = append(domains, strings.Fields(value)...)
		case "dnssec":
			lv := strings.ToLower(value)
			dnssec = lv == "yes" || lv == "true" || lv == "allow-downgrade"
		case "dnsovertls":
			lv := strings.ToLower(value)
			if lv == "yes" || lv == "opportunistic" {
				protocol = ProtocolDoT
			}
		}
	}

	out := make([]Resolver, 0, len(servers)+len(fallback))
	for _, s := range servers {
		out = append(out, mkResolved(s, domains, dnssec, protocol, filePath, hash, false))
	}
	for _, s := range fallback {
		out = append(out, mkResolved(s, domains, dnssec, protocol, filePath, hash, true))
	}
	return out
}

// mkResolved builds one systemd-resolved Resolver. The `is_fallback`
// flag is reflected via Priority (fallback = priority 100).
func mkResolved(server string, domains []string, dnssec bool, proto Protocol, filePath, hash string, fallback bool) Resolver {
	port := portForProtocol(proto)
	r := Resolver{
		Source:        SourceSystemdResolved,
		Scope:         ScopeSystem,
		Server:        server,
		Port:          port,
		Protocol:      proto,
		SearchDomains: append([]string(nil), domains...),
		IsDNSSEC:      dnssec,
		FilePath:      filePath,
		FileHash:      hash,
	}
	if fallback {
		r.Priority = 100
	}
	AnnotateSecurity(&r)
	return r
}

func portForProtocol(p Protocol) int {
	switch p {
	case ProtocolDoT:
		return 853
	case ProtocolDoH:
		return 443
	case ProtocolQUIC:
		return 853
	case ProtocolUDP, ProtocolTCP, ProtocolUnknown:
		return 53
	}
	return 53
}

// ParseNetworkManagerKeyfile walks an NM connection profile. Grammar:
//
//	[connection]
//	id=Wired
//	interface-name=eth0
//
//	[ipv4]
//	dns=8.8.8.8;1.1.1.1;
//	dns-search=corp.local;
//
//	[ipv6]
//	dns=2606:4700:4700::1111;
//	dns-search=corp.local;
//
// Each dns= server yields one Resolver. interface-name + id set the
// scope to "interface".
func ParseNetworkManagerKeyfile(raw []byte, filePath string) []Resolver {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		section  string
		iface    string
		v4Server []string
		v4Search []string
		v6Server []string
		v6Search []string
	)
	for _, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			section = strings.ToLower(strings.Trim(clean, "[]"))
			continue
		}
		key, value, ok := splitKV(clean)
		if !ok {
			continue
		}
		switch section {
		case "connection":
			if strings.EqualFold(key, "interface-name") {
				iface = value
			}
		case "ipv4":
			switch strings.ToLower(key) {
			case "dns":
				v4Server = append(v4Server, splitSemicolon(value)...)
			case "dns-search":
				v4Search = append(v4Search, splitSemicolon(value)...)
			}
		case "ipv6":
			switch strings.ToLower(key) {
			case "dns":
				v6Server = append(v6Server, splitSemicolon(value)...)
			case "dns-search":
				v6Search = append(v6Search, splitSemicolon(value)...)
			}
		}
	}

	out := make([]Resolver, 0, len(v4Server)+len(v6Server))
	for _, s := range v4Server {
		out = append(out, mkNM(s, v4Search, iface, filePath, hash))
	}
	for _, s := range v6Server {
		out = append(out, mkNM(s, v6Search, iface, filePath, hash))
	}
	return out
}

func mkNM(server string, domains []string, iface, filePath, hash string) Resolver {
	r := Resolver{
		Source:        SourceNetworkManager,
		Scope:         ScopeInterface,
		InterfaceName: iface,
		Server:        server,
		Port:          53,
		Protocol:      ProtocolUDP,
		SearchDomains: append([]string(nil), domains...),
		FilePath:      filePath,
		FileHash:      hash,
	}
	AnnotateSecurity(&r)
	return r
}

// -- shared helpers ------------------------------------------------------

func splitLines(raw []byte) []string {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	var out []string
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}

func stripComment(line string) string {
	// `#` is a comment leader only when it begins the line or is
	// preceded by whitespace. dnsmasq uses `host#port` syntax where
	// the `#` is value-internal and must NOT be stripped.
	if i := commentIndex(line, '#'); i >= 0 {
		line = line[:i]
	}
	if i := strings.IndexByte(line, ';'); i >= 0 && !looksLikeNMValue(line, i) {
		line = line[:i]
	}
	return line
}

// commentIndex returns the first position where `c` starts a comment
// — either at byte 0, or preceded by whitespace. Returns -1 otherwise.
func commentIndex(line string, c byte) int {
	for i := 0; i < len(line); i++ {
		if line[i] != c {
			continue
		}
		if i == 0 {
			return i
		}
		prev := line[i-1]
		if prev == ' ' || prev == '\t' {
			return i
		}
	}
	return -1
}

// looksLikeNMValue reports whether the `;` at offset `i` is more
// likely an NM dns= list separator than a comment leader. We treat
// `;` as a value separator when the part before it contains `=`.
func looksLikeNMValue(line string, i int) bool {
	return strings.Contains(line[:i], "=")
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func splitSemicolon(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ";") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseDnsmasqConf walks /etc/dnsmasq.conf (or a drop-in under
// /etc/dnsmasq.d/). Grammar per dnsmasq(8):
//
//	server=1.1.1.1
//	server=8.8.8.8#53
//	server=/corp.local/10.0.0.53     (per-domain routing)
//	no-resolv
//	domain=corp.local
//
// We emit one Resolver per `server=` line. Per-domain routing populates
// RoutedDomain + Scope=per-domain.
func ParseDnsmasqConf(raw []byte, filePath string) []Resolver {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var out []Resolver
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		key, value, ok := splitKV(clean)
		if !ok {
			continue
		}
		if !strings.EqualFold(key, "server") {
			continue
		}
		r := parseDnsmasqServerValue(value)
		r.Source = SourceDnsmasq
		r.FilePath = filePath
		r.FileHash = hash
		r.LineNo = i + 1
		r.RawLine = clean
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxResolvers {
			break
		}
	}
	return out
}

// parseDnsmasqServerValue handles the four `server=` shapes:
//
//	1.1.1.1
//	1.1.1.1#5353
//	/corp.local/10.0.0.53
//	/corp.local/10.0.0.53#5353
func parseDnsmasqServerValue(v string) Resolver {
	r := Resolver{
		Scope:    ScopeSystem,
		Port:     53,
		Protocol: ProtocolUDP,
	}
	if strings.HasPrefix(v, "/") {
		// /domain/server[#port]
		parts := strings.SplitN(v, "/", 3)
		if len(parts) == 3 {
			r.RoutedDomain = parts[1]
			r.Scope = ScopePerDomain
			v = parts[2]
		}
	}
	if i := strings.IndexByte(v, '#'); i >= 0 {
		if p, err := strconv.Atoi(strings.TrimSpace(v[i+1:])); err == nil {
			r.Port = p
		}
		v = v[:i]
	}
	r.Server = strings.TrimSpace(v)
	return r
}
