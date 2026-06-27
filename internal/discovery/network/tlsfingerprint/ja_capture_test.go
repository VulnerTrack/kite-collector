package tlsfingerprint

import (
	"bytes"
	"context"
	"crypto/md5" //#nosec G501 -- JA3S spec mandates MD5
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// buildServerHelloRecord assembles a minimal record-layer + handshake
// + ServerHello payload that parseServerHello can chew through. Used
// to exercise the parser without needing a real TLS handshake.
//
//	version: TLS 1.2 (0x0303)
//	cipher: TLS_AES_128_GCM_SHA256 (0x1301)
//	extensions:
//	  supported_versions (0x002b) → TLS 1.3
//	  ALPN (0x0010) → "h2"
func buildServerHelloRecord() []byte {
	body := &bytes.Buffer{}
	// LegacyVersion 0x0303 (TLS 1.2)
	body.WriteByte(0x03)
	body.WriteByte(0x03)
	// Random (32 zero bytes is fine for test purposes)
	body.Write(make([]byte, 32))
	// SessionID len + body
	body.WriteByte(0x00)
	// CipherSuite 0x1301 (TLS_AES_128_GCM_SHA256)
	body.WriteByte(0x13)
	body.WriteByte(0x01)
	// CompressionMethod 0x00
	body.WriteByte(0x00)

	// Extensions
	exts := &bytes.Buffer{}
	// supported_versions ext: type 0x002b, len 2, body 0x0304 (TLS 1.3)
	exts.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	// ALPN ext: type 0x0010, then len-prefixed list, then proto len + bytes.
	// list = u16(3) | u8(2) | "h2"
	alpn := []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'}
	exts.Write(alpn)

	body.WriteByte(byte(exts.Len() >> 8))
	body.WriteByte(byte(exts.Len()))
	body.Write(exts.Bytes())

	// Handshake header: type(2)=ServerHello, len(3)
	hs := &bytes.Buffer{}
	hs.WriteByte(0x02)
	bodyLen := body.Len()
	hs.WriteByte(byte(bodyLen >> 16))
	hs.WriteByte(byte(bodyLen >> 8))
	hs.WriteByte(byte(bodyLen))
	hs.Write(body.Bytes())

	// Record header: type 22 (handshake), legacy ver 0x0303, length(2)
	rec := &bytes.Buffer{}
	rec.WriteByte(0x16)
	rec.WriteByte(0x03)
	rec.WriteByte(0x03)
	rec.WriteByte(byte(hs.Len() >> 8))
	rec.WriteByte(byte(hs.Len()))
	rec.Write(hs.Bytes())

	return rec.Bytes()
}

func TestParseServerHello_Basic(t *testing.T) {
	buf := buildServerHelloRecord()
	sh, err := parseServerHello(buf)
	if err != nil {
		t.Fatalf("parseServerHello: %v", err)
	}
	if sh.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion: got %#x want 0x0303", sh.LegacyVersion)
	}
	if sh.SelectedVersion != 0x0304 {
		t.Errorf("SelectedVersion: got %#x want 0x0304 (TLS1.3 via supported_versions)", sh.SelectedVersion)
	}
	if sh.SelectedCipher != 0x1301 {
		t.Errorf("SelectedCipher: got %#x want 0x1301", sh.SelectedCipher)
	}
	if sh.ALPN != "h2" {
		t.Errorf("ALPN: got %q want h2", sh.ALPN)
	}
	// supported_versions(0x002b) + ALPN(0x0010)
	if len(sh.Extensions) != 2 {
		t.Fatalf("extensions count: got %d want 2", len(sh.Extensions))
	}
}

func TestParseServerHello_RejectsNonHandshake(t *testing.T) {
	buf := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if _, err := parseServerHello(buf); err == nil {
		t.Fatalf("expected error on non-handshake record")
	}
}

func TestParseServerHello_ShortBuffer(t *testing.T) {
	if _, err := parseServerHello(nil); err == nil {
		t.Fatalf("expected error on nil buffer")
	}
	if _, err := parseServerHello([]byte{0x16, 0x03}); err == nil {
		t.Fatalf("expected error on truncated record header")
	}
}

func TestJA3SString_MatchesSpec(t *testing.T) {
	sh := &serverHello{
		SelectedVersion: 0x0303,
		SelectedCipher:  0xc02f,
		Extensions:      []uint16{65281, 0, 11, 35, 23, 43, 13},
	}
	got := JA3SString(sh)
	want := "771,49199,65281-0-11-35-23-43-13"
	if got != want {
		t.Fatalf("JA3SString:\n got=%q\nwant=%q", got, want)
	}
	digestGot := JA3SDigest(sh)
	sum := md5.Sum([]byte(want)) //#nosec G401
	digestWant := hex.EncodeToString(sum[:])
	if digestGot != digestWant {
		t.Fatalf("JA3SDigest: got %q want %q", digestGot, digestWant)
	}
}

func TestJA4SString_TLS13H2(t *testing.T) {
	sh := &serverHello{
		SelectedVersion: 0x0304,
		SelectedCipher:  0x1301,
		Extensions:      []uint16{0x002b, 0x0010},
		ALPN:            "h2",
	}
	got := JA4SString(sh)
	if !strings.HasPrefix(got, "t1302h2_1301_") {
		t.Fatalf("JA4SString: got %q, expected prefix t1302h2_1301_", got)
	}
	// Verify hash component: SHA256(sorted ext list hex joined by ',')[0:6] hex'd.
	parts := []string{"0010", "002b"} // sorted ascending
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	wantHash := hex.EncodeToString(sum[:6])
	if !strings.HasSuffix(got, "_"+wantHash) {
		t.Fatalf("JA4SString hash suffix: got %q, want suffix _%s", got, wantHash)
	}
}

func TestJA4SString_NoALPN(t *testing.T) {
	sh := &serverHello{
		SelectedVersion: 0x0303,
		SelectedCipher:  0xc02f,
		Extensions:      []uint16{0, 23, 11},
	}
	got := JA4SString(sh)
	if !strings.HasPrefix(got, "t120300_c02f_") {
		t.Fatalf("JA4SString: got %q, expected prefix t120300_c02f_", got)
	}
}

func TestJA4Version(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0xffff, "00"},
	}
	for _, c := range cases {
		if got := ja4Version(c.v); got != c.want {
			t.Errorf("ja4Version(%#x): got %q want %q", c.v, got, c.want)
		}
	}
}

func TestJA4ALPN(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"h3", "h3"},
		{"grpc-exp", "gr"},
		{"", "00"},
		{"x", "xx"},
		{"acme-tls/1", "a1"},
	}
	for _, c := range cases {
		if got := ja4ALPN(c.in); got != c.want {
			t.Errorf("ja4ALPN(%q): got %q want %q", c.in, got, c.want)
		}
	}
}

func TestEndToEndScan_PopulatesJA3SAndJA4S(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "x.example", IssuerCN: "T",
		SANs: []string{"x.example"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()

	s := NewScanner(nil)
	res, err := s.Scan(context.Background(), host, port, ScanOptions{SNI: "x.example"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.ServerJA3S == "" {
		t.Fatalf("expected ServerJA3S populated, got %+v", res)
	}
	if res.ServerJA4S == "" {
		t.Fatalf("expected ServerJA4S populated, got %+v", res)
	}
	if !strings.HasPrefix(res.ServerJA4S, "t1") {
		t.Fatalf("expected JA4S to start with t1*, got %q", res.ServerJA4S)
	}
	if len(res.ServerJA3S) != 32 {
		t.Fatalf("expected 32-char MD5 JA3S, got %q (len %d)", res.ServerJA3S, len(res.ServerJA3S))
	}
}
