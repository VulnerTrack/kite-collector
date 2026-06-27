package intranetweb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Multi-protocol name-discovery probes. Each probe targets a single
// L4 service, parses the protocol just enough to extract the server-
// asserted hostname, and returns (host, signal, error). All probes
// share a small per-target wall-clock budget so a /24 sweep stays
// bounded.
//
// Signal-tier ranking (companion to docs/hostname-signals.md):
//
//   Tier A  — operator-curated, no network round-trip.
//   Tier B  — server self-asserted on the wire, cryptographically
//             signed (TLS SAN, SSH host certificate).
//   Tier C  — server self-asserted on the wire, unsigned but on a
//             live socket (SSH banner, SMTP HELO, mDNS, SNMP sysName,
//             LDAP rootDSE).
//   Tier D  — third-party assertion; spoofable but cheap (DNS PTR,
//             NetBIOS, SSDP friendlyName, WS-Discovery).
//   Tier E  — heuristic / derived hint (DHCP hostname, Server header).
//   Tier F  — synthetic (IP fallback).
//
// The MultiSourceNameResolver below queries multiple probes in
// parallel and picks the highest-tier non-empty result.

// SignalTier is the reliability-tier letter rank for a HostSignal.
// Lower letter (A) beats higher letter (F).
type SignalTier byte

const (
	TierA SignalTier = 'A'
	TierB SignalTier = 'B'
	TierC SignalTier = 'C'
	TierD SignalTier = 'D'
	TierE SignalTier = 'E'
	TierF SignalTier = 'F'
)

// Additional HostSignal constants from the catalog, beyond the five
// already wired by the HTTP probe in probe.go.
const (
	HostSignalSSHBanner     HostSignal = "ssh-banner"
	HostSignalSMTPHELO      HostSignal = "smtp-helo"
	HostSignalFTPBanner     HostSignal = "ftp-banner"
	HostSignalIMAPGreeting  HostSignal = "imap-greeting"
	HostSignalNetBIOS       HostSignal = "netbios-nbstat"
	HostSignalSSDP          HostSignal = "ssdp-upnp"
	HostSignalmDNS          HostSignal = "mdns-ptr"
	HostSignalLLDP          HostSignal = "lldp-system-name"
	HostSignalSNMP          HostSignal = "snmp-sysname"
	HostSignalSMBNegotiate  HostSignal = "smb-negotiate"
	HostSignalLDAPRootDSE   HostSignal = "ldap-rootdse"
	HostSignalHTTPRedirect  HostSignal = "http-redirect"
	HostSignalServerHeader  HostSignal = "http-server-header"
	HostSignalDHCPHostname  HostSignal = "dhcp-hostname"
	HostSignalSSHHostCert   HostSignal = "ssh-host-cert"
	HostSignalBluetoothName HostSignal = "bluetooth-name"
)

// TierOf returns the reliability tier (A-F) for a HostSignal. Maps
// each signal to its catalog tier. Unknown signals get Tier F so
// they're always beaten by any named source.
func TierOf(s HostSignal) SignalTier {
	switch s {
	case HostSignalExplicit:
		return TierA
	case HostSignalTLSSAN, HostSignalTLSCN, HostSignalSSHHostCert,
		HostSignalBluetoothName:
		return TierB
	case HostSignalSSHBanner, HostSignalSMTPHELO, HostSignalFTPBanner,
		HostSignalIMAPGreeting, HostSignalmDNS, HostSignalSNMP,
		HostSignalSMBNegotiate, HostSignalLDAPRootDSE,
		HostSignalHTTPRedirect:
		return TierC
	case HostSignalNetBIOS, HostSignalSSDP, HostSignalLLDP,
		HostSignalReverseDNS:
		return TierD
	case HostSignalServerHeader, HostSignalDHCPHostname:
		return TierE
	case HostSignalIP:
		return TierF
	}
	return TierF
}

// NameResult is the standard return for any single-protocol name
// probe. Empty Host means the probe did not produce a name (timeout,
// connection refused, banner unparseable, etc.).
type NameResult struct {
	Err    error
	Host   string
	Signal HostSignal
}

// NameProbe is the contract every protocol probe satisfies. Each
// implementation is responsible for its own connect / read / parse
// logic and MUST respect ctx cancellation.
type NameProbe interface {
	Probe(ctx context.Context, ip string) NameResult
}

// DefaultNameProbeTimeout caps any single-protocol name probe.
const DefaultNameProbeTimeout = 1500 * time.Millisecond

// ---- SSH banner (Tier C) ------------------------------------------

// SSHBannerProbe reads the first banner line from TCP 22. OpenSSH on
// Debian / Ubuntu often suffixes the hostname:
//
//	SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 myhost
//
// Some distros include only `SSH-2.0-OpenSSH_X.Y`; in that case the
// probe yields no name.
type SSHBannerProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for SSH.
func (p SSHBannerProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 22
	}
	host, err := dialAndReadLine(ctx, p.Dial, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(port)),
		probeTimeout(p.Timeout), nil)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseSSHBanner(host)
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalSSHBanner}
}

// ParseSSHBanner extracts the trailing-comment hostname from an SSH
// banner line. Returns empty unless the trailing token is clearly a
// hostname rather than an OS / distro suffix. Acceptance rules:
//
//   - ≥ 3 whitespace-separated fields: trailing token wins if it
//     looks like a hostname.
//   - exactly 2 fields: trailing token wins only when it carries a
//     dot AND is not version-like (no `<letter><digit>` chunk
//     before the first dot).
//
// Otherwise we return empty — many distros suffix `Ubuntu-3ubuntu0.7`
// or `Debian-2` without a hostname, and we'd rather miss a name than
// fabricate one.
func ParseSSHBanner(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "SSH-") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	last := fields[len(fields)-1]
	if !looksLikeHostname(last) {
		return ""
	}
	if len(fields) >= 3 {
		return last
	}
	// 2 fields: tighter heuristic — must look like an FQDN.
	if !looksLikeFQDN(last) {
		return ""
	}
	return last
}

// ---- SMTP HELO / EHLO banner (Tier C) -----------------------------

// SMTPBannerProbe reads the first `220` line from TCP 25 / 587 / 465
// (caller picks the port). A typical banner looks like:
//
//	220 mx1.example.com ESMTP Postfix
type SMTPBannerProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for SMTP.
func (p SMTPBannerProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 25
	}
	line, err := dialAndReadLine(ctx, p.Dial, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(port)),
		probeTimeout(p.Timeout), nil)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseSMTPBanner(line)
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalSMTPHELO}
}

// ParseSMTPBanner extracts the hostname from an SMTP 220 banner.
// Requires the first non-status-code token to look like an FQDN
// (contain a dot, not start with a digit). Looser greeting forms
// (`220 some text`) intentionally yield empty rather than guess.
func ParseSMTPBanner(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "220") {
		return ""
	}
	// SMTP multi-line continuations (`220-`) carry no hostname on
	// their own; we want the final `220 ` line.
	if strings.HasPrefix(line, "220-") {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "220"))
	tokens := strings.Fields(rest)
	if len(tokens) == 0 {
		return ""
	}
	first := tokens[0]
	if !looksLikeFQDN(first) {
		return ""
	}
	return first
}

// ---- FTP 220 banner (Tier C) --------------------------------------

// FTPBannerProbe reads the first `220` line from TCP 21. Banner shape
// is identical to SMTP — we reuse ParseSMTPBanner.
type FTPBannerProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for FTP.
func (p FTPBannerProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 21
	}
	line, err := dialAndReadLine(ctx, p.Dial, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(port)),
		probeTimeout(p.Timeout), nil)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseSMTPBanner(line) // shape is identical
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalFTPBanner}
}

// ---- IMAP greeting (Tier C) ---------------------------------------

// IMAPGreetingProbe reads the first `* OK` line from TCP 143 / 993.
// Typical greeting:
//
//   - OK [CAPABILITY ...] mail.example.com IMAP4rev1 ready
type IMAPGreetingProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for IMAP.
func (p IMAPGreetingProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 143
	}
	line, err := dialAndReadLine(ctx, p.Dial, "tcp",
		net.JoinHostPort(ip, strconv.Itoa(port)),
		probeTimeout(p.Timeout), nil)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseIMAPGreeting(line)
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalIMAPGreeting}
}

// ParseIMAPGreeting extracts the hostname from an IMAP `* OK ...` line.
func ParseIMAPGreeting(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "* OK") {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "* OK"))
	// IMAP greetings sometimes include `[CAPABILITY ...]` brackets
	// that contain spaces. Strip the first `[...]` block.
	if open := strings.Index(rest, "["); open == 0 {
		if close := strings.Index(rest, "]"); close > 0 && close < len(rest) {
			rest = strings.TrimSpace(rest[close+1:])
		}
	}
	for _, tok := range strings.Fields(rest) {
		if looksLikeHostname(tok) {
			return tok
		}
	}
	return ""
}

// ---- NetBIOS NBSTAT (Tier D) --------------------------------------

// NBSTATProbe sends a Node Status query to UDP 137 and parses the
// returned name table. The first entry whose suffix byte is 0x00
// (workstation) or 0x20 (server) is the host's primary name.
type NBSTATProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for NetBIOS.
func (p NBSTATProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 137
	}
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	t := probeTimeout(p.Timeout)
	dCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	conn, err := dial(dCtx, "udp",
		net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return NameResult{Err: err}
	}
	defer func() { _ = conn.Close() }()
	if d, ok := dCtx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if _, werr := conn.Write(buildNBSTATQuery()); werr != nil {
		return NameResult{Err: werr}
	}
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseNBSTATResponse(resp[:n])
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalNetBIOS}
}

// buildNBSTATQuery builds the standard NBSTAT query payload — a
// minimal 50-byte NetBIOS Name Service packet asking for the node
// status of the wildcard name `*`. RFC 1002.
func buildNBSTATQuery() []byte {
	// 16-byte fixed NetBIOS NS header + wildcard query body.
	buf := make([]byte, 0, 50)
	// Transaction ID = 0x1234 (any).
	buf = append(buf, 0x12, 0x34)
	// Flags = 0x0010 (standard query, recursion not desired).
	buf = append(buf, 0x00, 0x10)
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf = append(buf, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Encoded name: length=32, then 'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' for `*`,
	// then null terminator.
	buf = append(buf, 0x20)
	buf = append(buf,
		'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	)
	buf = append(buf, 0x00)
	// QTYPE=NBSTAT(0x0021), QCLASS=IN(0x0001).
	buf = append(buf, 0x00, 0x21, 0x00, 0x01)
	return buf
}

// ParseNBSTATResponse extracts the first WORKSTATION or SERVER name
// from a NetBIOS Node Status reply. Returns "" when the response is
// truncated, malformed, or only carries group names.
//
// NBSTAT response layout: 12-byte header + answer-section
// (variable-length encoded name) + RDATA. RDATA starts with a
// 1-byte name-count, followed by name-count * 18-byte entries
// (15-byte name + 1-byte suffix + 2-byte flags). Suffix 0x00 =
// workstation, 0x20 = server. Group entries have flag bit 0x8000.
func ParseNBSTATResponse(b []byte) string {
	// Minimum sensible response size: 12 hdr + 34 encoded name +
	// 10 RDATA-header + at least one 18-byte name entry.
	if len(b) < 12+34+10+18 {
		return ""
	}
	// Skip the 12-byte NS header. The answer section begins with the
	// encoded query name (1-byte length + 32 ASCII bytes + null = 34).
	off := 12 + 34
	// TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) = 10 bytes.
	if off+10 > len(b) {
		return ""
	}
	off += 10
	if off >= len(b) {
		return ""
	}
	count := int(b[off])
	off++
	for i := 0; i < count; i++ {
		if off+18 > len(b) {
			return ""
		}
		name := strings.TrimRight(string(b[off:off+15]), " \x00")
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16 : off+18])
		off += 18
		// Skip group names (high bit set) and active-directory groups.
		if flags&0x8000 != 0 {
			continue
		}
		if suffix == 0x00 || suffix == 0x20 {
			if name != "" && looksLikeHostname(name) {
				return name
			}
		}
	}
	return ""
}

// ---- SSDP / UPnP M-SEARCH (Tier D) --------------------------------

// SSDPProbe sends an HTTP-over-UDP M-SEARCH to UDP 1900 (unicast,
// not multicast — caller supplies a single IP) and parses the
// LOCATION header out of the response. The friendlyName lives in
// the description XML at LOCATION; this probe stops at extracting
// LOCATION (caller can dereference with the HTTP probe).
type SSDPProbe struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Port    int
	Timeout time.Duration
}

// Probe implements NameProbe for SSDP.
func (p SSDPProbe) Probe(ctx context.Context, ip string) NameResult {
	port := p.Port
	if port == 0 {
		port = 1900
	}
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	t := probeTimeout(p.Timeout)
	dCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	conn, err := dial(dCtx, "udp",
		net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return NameResult{Err: err}
	}
	defer func() { _ = conn.Close() }()
	if d, ok := dCtx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if _, werr := conn.Write(buildSSDPQuery(ip, port)); werr != nil {
		return NameResult{Err: werr}
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return NameResult{Err: err}
	}
	name := ParseSSDPResponse(resp[:n])
	if name == "" {
		return NameResult{}
	}
	return NameResult{Host: name, Signal: HostSignalSSDP}
}

// buildSSDPQuery builds an HTTPMU M-SEARCH packet targeted at a
// single host. We use ST=`ssdp:all` to maximise replies and MX=1
// (max-wait 1 second) so passive devices reply promptly.
func buildSSDPQuery(ip string, port int) []byte {
	return []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: " + net.JoinHostPort(ip, strconv.Itoa(port)) + "\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: ssdp:all\r\n" +
			"\r\n",
	)
}

// ParseSSDPResponse extracts the LOCATION-header hostname from an
// SSDP M-SEARCH response. The response is a plain HTTP/1.1 status
// line + headers — we parse the Location URL and return its host
// component. Useful when the LOCATION points at a description.xml
// served from a real DNS name rather than the IP.
func ParseSSDPResponse(b []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			continue
		}
		rest := strings.TrimSpace(line[len("LOCATION:"):])
		// http(s)://<host>:<port>/...
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		// Strip the port suffix.
		if h, _, err := net.SplitHostPort(rest); err == nil {
			rest = h
		}
		if looksLikeHostname(rest) {
			return rest
		}
	}
	return ""
}

// ---- MultiSourceNameResolver --------------------------------------

// MultiSourceNameResolver runs multiple NameProbe implementations in
// parallel against a single IP and selects the result with the
// highest signal tier. Ties are broken in the order the probes were
// registered (caller controls priority).
type MultiSourceNameResolver struct {
	Probes  []NameProbe
	Timeout time.Duration
}

// Resolve runs all probes in parallel, waits for the deadline (or
// for every probe to return), and returns the best (host, signal).
// Returns ("", "", nil) when no probe produced a name.
//
// All probe errors are aggregated into the returned error for
// observability; they do not affect the chosen result.
func (m MultiSourceNameResolver) Resolve(ctx context.Context, ip string) (string, HostSignal, error) {
	if len(m.Probes) == 0 {
		return "", "", nil
	}
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make(chan NameResult, len(m.Probes))
	for _, p := range m.Probes {
		probe := p
		go func() {
			results <- probe.Probe(runCtx, ip)
		}()
	}

	var bestHost string
	var bestSignal HostSignal
	bestTier := SignalTier('Z') // worse than any valid tier
	var errs []error
	for i := 0; i < len(m.Probes); i++ {
		select {
		case r := <-results:
			if r.Err != nil {
				errs = append(errs, r.Err)
			}
			if r.Host == "" {
				continue
			}
			if t := TierOf(r.Signal); t < bestTier {
				bestTier = t
				bestHost = r.Host
				bestSignal = r.Signal
			}
		case <-runCtx.Done():
			return bestHost, bestSignal, errors.Join(errs...)
		}
	}
	return bestHost, bestSignal, errors.Join(errs...)
}

// ---- shared helpers -----------------------------------------------

func probeTimeout(t time.Duration) time.Duration {
	if t <= 0 {
		return DefaultNameProbeTimeout
	}
	return t
}

// dialAndReadLine opens a TCP connection (using the optional dial
// func) and returns the first newline-delimited line. Closes the
// connection on return. Used by SSH / SMTP / FTP / IMAP banner
// probes, all of which send a server-first greeting.
//
// `clientGreeting` is sent BEFORE reading the line when non-nil
// (currently unused but reserved for protocols that need a probe
// trigger).
func dialAndReadLine(ctx context.Context, dialFn func(ctx context.Context, network, addr string) (net.Conn, error),
	network, addr string, t time.Duration, clientGreeting []byte,
) (string, error) {
	dial := dialFn
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	conn, err := dial(dCtx, network, addr)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if d, ok := dCtx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if len(clientGreeting) > 0 {
		if _, werr := conn.Write(clientGreeting); werr != nil {
			return "", fmt.Errorf("greet: %w", werr)
		}
	}
	r := bufio.NewReader(io.LimitReader(conn, 4096))
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// looksLikeFQDN is the stricter sibling of looksLikeHostname: it
// requires a dot AND a non-version-like first label, used by the
// SSH and SMTP banner parsers to reject OS-distro suffixes like
// `Ubuntu-3ubuntu0.7`. Distro-version labels follow `<word>-<digit>`
// shape (the hyphen-then-digit is the key tell), whereas legitimate
// hostnames use the hyphen to separate words (`mail-1` rare; usually
// `mail1` or `mx1`).
func looksLikeFQDN(s string) bool {
	s = strings.TrimSpace(s)
	if !looksLikeHostname(s) {
		return false
	}
	dot := strings.Index(s, ".")
	if dot <= 0 || dot >= len(s)-1 {
		return false
	}
	first := s[:dot]
	// Reject labels whose first character is a digit (1.2.3.4 IPs,
	// version strings starting with a number).
	if first[0] >= '0' && first[0] <= '9' {
		return false
	}
	// Reject distro-version labels matching `<word>-<digit>` —
	// `Ubuntu-3ubuntu0`, `Debian-2`, `Fedora-39`, etc.
	for i := 0; i+1 < len(first); i++ {
		if first[i] == '-' && first[i+1] >= '0' && first[i+1] <= '9' {
			return false
		}
	}
	return true
}

// looksLikeHostname is a tolerant check used by the banner parsers
// to decide whether a trailing token is plausibly a hostname rather
// than a version string or comment. The bar is intentionally low
// because intranet hosts have weird names.
func looksLikeHostname(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || len(s) > 253 {
		return false
	}
	// Reject anything with whitespace, slashes, parens, or other
	// non-hostname-y punctuation.
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '.', r == '_':
			continue
		default:
			return false
		}
	}
	// At least one letter — pure numeric is probably an IP or
	// version string.
	hasLetter := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}
