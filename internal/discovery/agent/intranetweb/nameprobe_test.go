package intranetweb

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTierOf(t *testing.T) {
	cases := []struct {
		signal HostSignal
		tier   SignalTier
	}{
		{HostSignalExplicit, TierA},
		{HostSignalTLSSAN, TierB},
		{HostSignalTLSCN, TierB},
		{HostSignalSSHHostCert, TierB},
		{HostSignalBluetoothName, TierB},
		{HostSignalSSHBanner, TierC},
		{HostSignalSMTPHELO, TierC},
		{HostSignalFTPBanner, TierC},
		{HostSignalIMAPGreeting, TierC},
		{HostSignalmDNS, TierC},
		{HostSignalSNMP, TierC},
		{HostSignalSMBNegotiate, TierC},
		{HostSignalLDAPRootDSE, TierC},
		{HostSignalHTTPRedirect, TierC},
		{HostSignalNetBIOS, TierD},
		{HostSignalSSDP, TierD},
		{HostSignalLLDP, TierD},
		{HostSignalReverseDNS, TierD},
		{HostSignalServerHeader, TierE},
		{HostSignalDHCPHostname, TierE},
		{HostSignalIP, TierF},
	}
	for _, c := range cases {
		if got := TierOf(c.signal); got != c.tier {
			t.Fatalf("TierOf(%q)=%c want %c", c.signal, got, c.tier)
		}
	}
}

func TestParseSSHBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 myhost":      "myhost",
		"SSH-2.0-OpenSSH_9.6 Debian-3 mailserver.example.com": "mailserver.example.com",
		"SSH-2.0-OpenSSH_8.0 server.example.com":              "server.example.com",
		"SSH-2.0-OpenSSH_8.0":                                 "",
		"SSH-1.99 dropbear":                                   "", // 2 fields, no dot
		"":                                                    "",
		"NOT-AN-SSH-BANNER":                                   "",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7":             "", // version-like
	}
	for in, want := range cases {
		if got := ParseSSHBanner(in); got != want {
			t.Fatalf("ParseSSHBanner(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseSMTPBanner(t *testing.T) {
	cases := map[string]string{
		"220 mx1.example.com ESMTP Postfix":  "mx1.example.com",
		"220-mail.example.com greetings":     "",
		"220 ":                               "",
		"":                                   "",
		"220 some other text":                "",
		"220 host.local ESMTP service ready": "host.local",
	}
	for in, want := range cases {
		if got := ParseSMTPBanner(in); got != want {
			t.Fatalf("ParseSMTPBanner(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseIMAPGreeting(t *testing.T) {
	cases := map[string]string{
		"* OK [CAPABILITY IMAP4rev1 ID] mail.example.com ready": "mail.example.com",
		"* OK mail.example.com IMAP4rev1 ready":                 "mail.example.com",
		"* OK Dovecot ready":                                    "Dovecot", // looksLikeHostname accepts single word
		"":                                                      "",
		"NOT-AN-IMAP-GREETING":                                  "",
	}
	for in, want := range cases {
		if got := ParseIMAPGreeting(in); got != want {
			t.Fatalf("ParseIMAPGreeting(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseNBSTATResponse(t *testing.T) {
	// Build a synthetic NBSTAT reply: 12 hdr + 34 encoded query name
	// + TYPE/CLASS/TTL/RDLENGTH (10) + 1 name-count + 18 per name.
	resp := make([]byte, 0, 100)
	resp = append(resp, 0x12, 0x34) // TID
	resp = append(resp, 0x84, 0x00) // flags = response
	resp = append(resp, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	// Encoded name (34 bytes): length=32, 32 ASCII bytes, null term.
	resp = append(resp, 0x20)
	for i := 0; i < 32; i++ {
		resp = append(resp, 'A')
	}
	resp = append(resp, 0x00)
	// TYPE+CLASS+TTL+RDLENGTH = 10 bytes (TTL=0, RDLENGTH=any).
	resp = append(resp, 0x00, 0x21, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x36)
	// Name count = 1.
	resp = append(resp, 0x01)
	// One name entry: 15-char padded name + suffix 0x00 + flags 0x0000.
	name := "MYWORKSTATION  "
	resp = append(resp, []byte(name)...)
	resp = append(resp, 0x00)       // suffix workstation
	resp = append(resp, 0x00, 0x00) // flags (no group bit)

	got := ParseNBSTATResponse(resp)
	if got != "MYWORKSTATION" {
		t.Fatalf("ParseNBSTATResponse=%q want MYWORKSTATION", got)
	}

	// Truncated response yields empty.
	if got := ParseNBSTATResponse(resp[:10]); got != "" {
		t.Fatalf("truncated must yield empty, got %q", got)
	}
}

func TestParseNBSTATResponseGroupOnly(t *testing.T) {
	// Same shape but with the group-flag bit set — must yield empty.
	resp := make([]byte, 0, 100)
	resp = append(resp, 0x12, 0x34, 0x84, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	resp = append(resp, 0x20)
	for i := 0; i < 32; i++ {
		resp = append(resp, 'A')
	}
	resp = append(resp, 0x00)
	resp = append(resp, 0x00, 0x21, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x36)
	resp = append(resp, 0x01)
	name := "WORKGROUP      "
	resp = append(resp, []byte(name)...)
	resp = append(resp, 0x1d)       // suffix master browser
	resp = append(resp, 0x80, 0x00) // flags: group-bit set
	if got := ParseNBSTATResponse(resp); got != "" {
		t.Fatalf("group entry must yield empty, got %q", got)
	}
}

func TestParseSSDPResponse(t *testing.T) {
	body := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://nas.example.local:5000/desc.xml\r\n" +
		"SERVER: Linux/4.4 UPnP/1.1 MiniDLNA/1.2.1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n")
	got := ParseSSDPResponse(body)
	if got != "nas.example.local" {
		t.Fatalf("ParseSSDPResponse=%q want nas.example.local", got)
	}

	// LOCATION pointing at a bare IP yields empty (no name).
	bodyIP := []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.10:5000/x.xml\r\n\r\n")
	if got := ParseSSDPResponse(bodyIP); got != "" {
		t.Fatalf("IP-only LOCATION must yield empty, got %q", got)
	}
}

func TestLooksLikeHostname(t *testing.T) {
	cases := map[string]bool{
		"myhost":                 true,
		"mailserver.example.com": true,
		"nas.example.local":      true,
		"a":                      false, // too short
		"192.168.1.1":            false, // pure numeric ip-like
		"":                       false,
		"OpenSSH_8.9p1":          true, // technically passes (letter+dot+digit)
		"host with spaces":       false,
		"host/with/slashes":      false,
	}
	for in, want := range cases {
		if got := looksLikeHostname(in); got != want {
			t.Fatalf("looksLikeHostname(%q)=%v want %v", in, got, want)
		}
	}
}

// fakeConn is a net.Conn that returns a canned response and accepts
// any write.
type fakeConn struct {
	read    []byte
	written []byte
	pos     int
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.pos >= len(f.read) {
		return 0, errors.New("eof")
	}
	n := copy(b, f.read[f.pos:])
	f.pos += n
	return n, nil
}

func (f *fakeConn) Write(b []byte) (int, error) {
	f.written = append(f.written, b...)
	return len(b), nil
}

func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func fakeDial(banner string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		return &fakeConn{read: []byte(banner + "\r\n")}, nil
	}
}

func TestSSHBannerProbe(t *testing.T) {
	p := SSHBannerProbe{
		Dial: fakeDial("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 myhost"),
	}
	r := p.Probe(context.Background(), "10.0.0.1")
	if r.Err != nil {
		t.Fatalf("err: %v", r.Err)
	}
	if r.Host != "myhost" {
		t.Fatalf("host=%q want myhost", r.Host)
	}
	if r.Signal != HostSignalSSHBanner {
		t.Fatalf("signal=%q want ssh-banner", r.Signal)
	}
}

func TestSMTPBannerProbe(t *testing.T) {
	p := SMTPBannerProbe{
		Dial: fakeDial("220 mx1.example.com ESMTP Postfix"),
	}
	r := p.Probe(context.Background(), "10.0.0.1")
	if r.Err != nil {
		t.Fatalf("err: %v", r.Err)
	}
	if r.Host != "mx1.example.com" {
		t.Fatalf("host=%q want mx1.example.com", r.Host)
	}
	if r.Signal != HostSignalSMTPHELO {
		t.Fatalf("signal=%q want smtp-helo", r.Signal)
	}
}

func TestFTPBannerProbe(t *testing.T) {
	p := FTPBannerProbe{
		Dial: fakeDial("220 ftp.example.com FTP server ready"),
	}
	r := p.Probe(context.Background(), "10.0.0.1")
	if r.Host != "ftp.example.com" {
		t.Fatalf("host=%q want ftp.example.com", r.Host)
	}
	if r.Signal != HostSignalFTPBanner {
		t.Fatalf("signal=%q want ftp-banner", r.Signal)
	}
}

func TestIMAPGreetingProbe(t *testing.T) {
	p := IMAPGreetingProbe{
		Dial: fakeDial("* OK [CAPABILITY IMAP4rev1] mail.example.com ready"),
	}
	r := p.Probe(context.Background(), "10.0.0.1")
	if r.Host != "mail.example.com" {
		t.Fatalf("host=%q want mail.example.com", r.Host)
	}
	if r.Signal != HostSignalIMAPGreeting {
		t.Fatalf("signal=%q want imap-greeting", r.Signal)
	}
}

// stubProbe is a NameProbe that returns a canned NameResult.
type stubProbe struct{ r NameResult }

func (s stubProbe) Probe(_ context.Context, _ string) NameResult { return s.r }

func TestMultiSourceNameResolver_TierWins(t *testing.T) {
	// Tier A (Explicit) must beat Tier C (SSH banner) which must beat
	// Tier D (NetBIOS) — independent of order in Probes.
	tierD := stubProbe{r: NameResult{Host: "nbhost", Signal: HostSignalNetBIOS}}
	tierC := stubProbe{r: NameResult{Host: "sshhost", Signal: HostSignalSSHBanner}}
	tierA := stubProbe{r: NameResult{Host: "explicit-host", Signal: HostSignalExplicit}}

	m := MultiSourceNameResolver{
		Probes:  []NameProbe{tierD, tierC, tierA},
		Timeout: time.Second,
	}
	host, sig, err := m.Resolve(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if host != "explicit-host" {
		t.Fatalf("host=%q want explicit-host", host)
	}
	if sig != HostSignalExplicit {
		t.Fatalf("signal=%q want explicit", sig)
	}
}

func TestMultiSourceNameResolver_EmptyResults(t *testing.T) {
	empty := stubProbe{r: NameResult{}}
	m := MultiSourceNameResolver{
		Probes:  []NameProbe{empty, empty},
		Timeout: time.Second,
	}
	host, sig, _ := m.Resolve(context.Background(), "10.0.0.1")
	if host != "" {
		t.Fatalf("host=%q want empty", host)
	}
	if sig != "" {
		t.Fatalf("signal=%q want empty", sig)
	}
}

func TestMultiSourceNameResolver_AggregatesErrors(t *testing.T) {
	errp := stubProbe{r: NameResult{Err: errors.New("boom")}}
	m := MultiSourceNameResolver{
		Probes:  []NameProbe{errp, errp},
		Timeout: time.Second,
	}
	_, _, err := m.Resolve(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("must aggregate probe errors")
	}
}

func TestMultiSourceNameResolver_NoProbes(t *testing.T) {
	m := MultiSourceNameResolver{}
	host, sig, err := m.Resolve(context.Background(), "10.0.0.1")
	if host != "" || sig != "" || err != nil {
		t.Fatalf("expected empty result, got (%q, %q, %v)", host, sig, err)
	}
}
