package timesync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceChrony), "chrony"},
		{string(SourceNTPd), "ntpd"},
		{string(SourceSystemdTimesyncd), "systemd-timesyncd"},
		{string(SourceOpenNTPd), "openntpd"},
		{string(SourceW32Time), "w32time"},
		{string(SourceSNTP), "sntp"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedDirectiveStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(DirectiveServer), "server"},
		{string(DirectivePeer), "peer"},
		{string(DirectivePool), "pool"},
		{string(DirectiveFallback), "fallback"},
		{string(DirectiveSNTPFallback), "sntp-fallback"},
		{string(DirectiveUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("directive drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedProtocolStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ProtocolNTP), "ntp"},
		{string(ProtocolNTS), "nts"},
		{string(ProtocolSNTP), "sntp"},
		{string(ProtocolAutokey), "autokey"},
		{string(ProtocolUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("protocol drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("server 0.pool.ntp.org iburst\n"))
	b := HashContents([]byte("server 0.pool.ntp.org iburst\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsPublicNTPServer(t *testing.T) {
	hits := []string{
		"0.pool.ntp.org",
		"3.ubuntu.pool.ntp.org",
		"time.google.com",
		"time.cloudflare.com",
		"ntp.ubuntu.com",
		"time.nist.gov",
		"ptbtime1.ptb.de",
	}
	for _, s := range hits {
		if !IsPublicNTPServer(s) {
			t.Fatalf("%q must flag public", s)
		}
	}
	miss := []string{
		"ntp.corp.local",
		"10.0.0.53",
		"",
		"timeserver.internal",
	}
	for _, s := range miss {
		if IsPublicNTPServer(s) {
			t.Fatalf("%q must NOT flag public", s)
		}
	}
}

func TestAnnotateSecurityFlagsPool(t *testing.T) {
	p := Peer{Server: "0.pool.ntp.org", Directive: DirectivePool}
	AnnotateSecurity(&p)
	if !p.IsPublicServer {
		t.Fatal("pool.ntp.org must flag public")
	}
	if !p.IsPoolMember {
		t.Fatal("pool directive must flag is_pool_member")
	}
}

// -- ParseChrony ---------------------------------------------------------

func TestParseChronyTypical(t *testing.T) {
	body := []byte(`# chrony.conf
server 0.pool.ntp.org iburst
server time.cloudflare.com iburst nts
pool 2.pool.ntp.org iburst maxsources 4
server 10.0.0.53 iburst key 12 minpoll 4 maxpoll 10
peer ntp.corp.local
keyfile /etc/chrony/chrony.keys
`)
	got := ParseChrony(body, "/etc/chrony/chrony.conf")
	if len(got) != 5 {
		t.Fatalf("len=%d, want 5: %+v", len(got), got)
	}

	// pool entry classified correctly.
	var pool Peer
	for _, p := range got {
		if p.Directive == DirectivePool {
			pool = p
		}
	}
	if !pool.IsPoolMember {
		t.Fatal("pool directive must flag IsPoolMember")
	}
	if !pool.IsPublicServer {
		t.Fatal("pool.ntp.org must flag IsPublicServer")
	}

	// NTS entry.
	var nts Peer
	for _, p := range got {
		if p.Server == "time.cloudflare.com" {
			nts = p
		}
	}
	if nts.Protocol != ProtocolNTS {
		t.Fatalf("nts protocol=%q", nts.Protocol)
	}
	if !nts.IsAuthenticated {
		t.Fatal("nts must flag IsAuthenticated")
	}
	if nts.Port != 4460 {
		t.Fatalf("nts port=%d (want 4460)", nts.Port)
	}

	// Internal corp server with key.
	var corpKey Peer
	for _, p := range got {
		if p.Server == "10.0.0.53" {
			corpKey = p
		}
	}
	if corpKey.KeyID != 12 {
		t.Fatalf("key_id=%d", corpKey.KeyID)
	}
	if !corpKey.IsAuthenticated {
		t.Fatal("shared-key server must flag IsAuthenticated")
	}
	if corpKey.MinPoll != 4 || corpKey.MaxPoll != 10 {
		t.Fatalf("poll bounds: min=%d max=%d", corpKey.MinPoll, corpKey.MaxPoll)
	}
	if corpKey.IsPublicServer {
		t.Fatal("10.0.0.53 must NOT flag public")
	}

	// Peer keyword.
	var peer Peer
	for _, p := range got {
		if p.Directive == DirectivePeer {
			peer = p
		}
	}
	if peer.Server != "ntp.corp.local" {
		t.Fatalf("peer server=%q", peer.Server)
	}
}

func TestParseChronyIburstAndPrefer(t *testing.T) {
	body := []byte("server 0.pool.ntp.org iburst prefer\n")
	got := ParseChrony(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].Iburst || !got[0].PreferFlag {
		t.Fatalf("flags: %+v", got[0])
	}
}

// -- ParseNTPd -----------------------------------------------------------

func TestParseNTPdTypical(t *testing.T) {
	body := []byte(`# ntp.conf
server 0.pool.ntp.org iburst
server 10.0.0.53 iburst autokey
server time.google.com iburst key 42
`)
	got := ParseNTPd(body, "/etc/ntp.conf")
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	var autokey Peer
	for _, p := range got {
		if p.Protocol == ProtocolAutokey {
			autokey = p
		}
	}
	if autokey.Server != "10.0.0.53" {
		t.Fatalf("autokey on %q", autokey.Server)
	}
	if !autokey.IsAuthenticated {
		t.Fatal("autokey must flag IsAuthenticated")
	}
	var key42 Peer
	for _, p := range got {
		if p.KeyID == 42 {
			key42 = p
		}
	}
	if !key42.IsAuthenticated {
		t.Fatal("key 42 must flag IsAuthenticated")
	}
	if !key42.IsPublicServer {
		t.Fatal("time.google.com still flags public even with key")
	}
}

// -- ParseTimesyncd ------------------------------------------------------

func TestParseTimesyncdTypical(t *testing.T) {
	body := []byte(`# timesyncd.conf
[Time]
NTP=10.0.0.53 ntp.corp.local
FallbackNTP=0.pool.ntp.org 1.pool.ntp.org
`)
	got := ParseTimesyncd(body, "/etc/systemd/timesyncd.conf")
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4: %+v", len(got), got)
	}
	for _, p := range got {
		if p.Protocol != ProtocolSNTP {
			t.Fatalf("timesyncd must produce SNTP, got %q", p.Protocol)
		}
	}
	// Public fallback flagged.
	var fallbackPublic Peer
	for _, p := range got {
		if p.Directive == DirectiveFallback && p.Server == "0.pool.ntp.org" {
			fallbackPublic = p
		}
	}
	if !fallbackPublic.IsPublicServer {
		t.Fatal("public fallback must flag IsPublicServer")
	}
}

func TestParseTimesyncdNonTimeSectionIgnored(t *testing.T) {
	body := []byte("[Other]\nNTP=1.1.1.1\n")
	got := ParseTimesyncd(body, "x")
	if len(got) != 0 {
		t.Fatalf("non-[Time] section: %+v", got)
	}
}

// -- ParseOpenNTPd -------------------------------------------------------

func TestParseOpenNTPdTypical(t *testing.T) {
	body := []byte(`# OpenNTPD
server 0.pool.ntp.org
servers pool.ntp.org
listen on *
`)
	got := ParseOpenNTPd(body, "/etc/openntpd/ntpd.conf")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	var poolPeer Peer
	for _, p := range got {
		if p.Directive == DirectivePool {
			poolPeer = p
		}
	}
	if !poolPeer.IsPoolMember {
		t.Fatal("OpenNTPD `servers` must classify as pool")
	}
}

// -- collector end-to-end ------------------------------------------------

func TestFileCollectorWalksAllSources(t *testing.T) {
	tmp := t.TempDir()
	chrony := filepath.Join(tmp, "chrony.conf")
	chronyDir := filepath.Join(tmp, "chrony.d")
	ntp := filepath.Join(tmp, "ntp.conf")
	timesyncd := filepath.Join(tmp, "timesyncd.conf")
	timesyncdDir := filepath.Join(tmp, "timesyncd.d")
	openntpd := filepath.Join(tmp, "openntpd.conf")

	for _, d := range []string{chronyDir, timesyncdDir} {
		must(t, os.MkdirAll(d, 0o755))
	}
	mustWrite(t, chrony, "server 10.0.0.53 iburst\n")
	mustWrite(t, filepath.Join(chronyDir, "00-extra.conf"),
		"pool 0.pool.ntp.org iburst\n")
	mustWrite(t, ntp, "server time.google.com iburst\n")
	mustWrite(t, timesyncd,
		"[Time]\nNTP=ntp.corp.local\nFallbackNTP=time.cloudflare.com\n")
	mustWrite(t, openntpd, "server 1.pool.ntp.org\n")

	c := &fileCollector{
		chronyConf:    chrony,
		chronyConfDir: chronyDir,
		ntpdConf:      ntp,
		timesyncdConf: timesyncd,
		timesyncdDir:  timesyncdDir,
		openntpdConf:  openntpd,
		readFile:      os.ReadFile,
		readDir:       os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 chrony + 1 chrony-d + 1 ntpd + 2 timesyncd + 1 openntpd = 6.
	if len(got) != 6 {
		t.Fatalf("want 6, got %d: %+v", len(got), got)
	}
	publicCount := 0
	for _, p := range got {
		if p.IsPublicServer {
			publicCount++
		}
	}
	// 0.pool, time.google.com, time.cloudflare.com, 1.pool = 4 public.
	if publicCount != 4 {
		t.Fatalf("public count=%d, want 4: %+v", publicCount, got)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		chronyConf:    "/nope",
		chronyConfDir: "/nope-dir",
		ntpdConf:      "/nope",
		timesyncdConf: "/nope",
		timesyncdDir:  "/nope-dir",
		openntpdConf:  "/nope",
		readFile:      os.ReadFile,
		readDir:       os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortPeersDeterministic(t *testing.T) {
	in := []Peer{
		{Source: SourceNTPd, Server: "z", Port: 123},
		{Source: SourceChrony, Server: "a", Port: 123},
		{Source: SourceChrony, Server: "a", Port: 4460},
	}
	SortPeers(in)
	if in[0].Source != SourceChrony || in[0].Port != 123 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Source != SourceNTPd {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -------------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
