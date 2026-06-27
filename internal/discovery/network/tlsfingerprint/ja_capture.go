package tlsfingerprint

import (
	"bytes"
	"crypto/md5" //#nosec G501 -- JA3S spec mandates MD5
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// JA3 / JA4 / JA4S background.
//
// JA3 (Salesforce 2017): MD5 of "SSLVersion,Ciphers,Extensions,SupportedGroups,EcPointFormats"
//   over the ClientHello. Identifies the client.
// JA3S (Salesforce 2017): MD5 of "SSLVersion,SelectedCipher,Extensions" over the
//   ServerHello. Identifies the server software/library.
// JA4 (FoxIO 2023): newer client fingerprint. Format
//   "t<ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_hash>" where each
//   hash is the first 12 hex chars of SHA256 over the sorted, comma-joined codes.
// JA4S (FoxIO 2023): server analogue. Format
//   "t<ver><ext_count><alpn>_<selected_cipher>_<ext_hash>".
// JA5 (Salesforce, never widely published): behavioural fingerprint of an *observed
//   client's* handshake history; not derivable from a single transaction. Not
//   applicable to a client-side scanner.
//
// crypto/tls does not expose ServerHello bytes through any public API. The
// trick we use: wrap net.Conn with a recorder that buffers every Read during
// the handshake. After tls.Conn.HandshakeContext returns, parse the buffer to
// find the first record-layer block with handshake-type=2 (ServerHello), and
// derive JA3S + JA4S from that.

// handshakeRecorder is a net.Conn wrapper that copies every Read into an
// internal buffer until Stop() is called. Goroutine-safe.
type handshakeRecorder struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	done bool
}

func newHandshakeRecorder(c net.Conn) *handshakeRecorder {
	return &handshakeRecorder{Conn: c}
}

// Read mirrors the underlying conn but tees bytes into buf while
// done is false.
func (r *handshakeRecorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if !r.done {
			_, _ = r.buf.Write(p[:n])
		}
		r.mu.Unlock()
	}
	return n, err
}

// Stop pauses recording. Future Reads pass through verbatim.
func (r *handshakeRecorder) Stop() {
	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
}

// snapshot returns a copy of the captured handshake bytes.
func (r *handshakeRecorder) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.buf.Len())
	copy(out, r.buf.Bytes())
	return out
}

// serverHello carries the fields we need to compute JA3S / JA4S.
type serverHello struct {
	// LegacyVersion is the TLS-record legacy version (in TLS 1.3 still
	// 0x0303). If a supported_versions extension is present, the
	// SelectedVersion field overrides it.
	LegacyVersion    uint16
	SelectedVersion  uint16
	SelectedCipher   uint16
	Extensions       []uint16 // in order of appearance
	ALPN             string   // first proto if multiple negotiated
}

// parseServerHello extracts the first ServerHello record from buf
// and returns a populated serverHello. Returns an error if buf does
// not begin with a parseable handshake record. We tolerate truncation:
// if any extension body extends past buf, we stop parsing extensions
// but return what we have.
func parseServerHello(buf []byte) (*serverHello, error) {
	// Record layer: ContentType(1) | LegacyVersion(2) | Length(2) | payload
	if len(buf) < 5 {
		return nil, errors.New("ja: buffer too short for record header")
	}
	if buf[0] != 22 { // 22 = handshake
		return nil, fmt.Errorf("ja: first record is not handshake (got %d)", buf[0])
	}
	recordLen := int(buf[3])<<8 | int(buf[4])
	if 5+recordLen > len(buf) {
		// Partial record — keep what we have.
		recordLen = len(buf) - 5
	}
	handshake := buf[5 : 5+recordLen]
	if len(handshake) < 4 {
		return nil, errors.New("ja: handshake header too short")
	}
	if handshake[0] != 2 { // 2 = ServerHello
		return nil, fmt.Errorf("ja: not a ServerHello (got %d)", handshake[0])
	}
	bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if 4+bodyLen > len(handshake) {
		bodyLen = len(handshake) - 4
	}
	body := handshake[4 : 4+bodyLen]

	// ServerHello body layout:
	//   LegacyVersion(2) | Random(32) | SessionIDLen(1) | SessionID(0..32)
	//   | CipherSuite(2) | CompressionMethod(1) | ExtensionsLen(2) | Extensions
	off := 0
	if len(body) < off+2+32+1 {
		return nil, errors.New("ja: ServerHello body too short")
	}
	sh := &serverHello{}
	sh.LegacyVersion = uint16(body[off])<<8 | uint16(body[off+1])
	off += 2
	off += 32 // skip random
	sessionIDLen := int(body[off])
	off++
	off += sessionIDLen
	if off+2+1 > len(body) {
		return nil, errors.New("ja: cipher_suite truncated")
	}
	sh.SelectedCipher = uint16(body[off])<<8 | uint16(body[off+1])
	off += 2
	off++ // compression method
	if off >= len(body) {
		// No extensions block (legal in TLS 1.0/1.1).
		return sh, nil
	}
	if off+2 > len(body) {
		return sh, nil
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	end := off + extLen
	if end > len(body) {
		end = len(body)
	}
	for off+4 <= end {
		extType := uint16(body[off])<<8 | uint16(body[off+1])
		off += 2
		thisLen := int(body[off])<<8 | int(body[off+1])
		off += 2
		if off+thisLen > end {
			// Truncated extension body — record the type and stop.
			sh.Extensions = append(sh.Extensions, extType)
			break
		}
		extBody := body[off : off+thisLen]
		sh.Extensions = append(sh.Extensions, extType)
		// supported_versions(0x002b) overrides LegacyVersion in TLS 1.3.
		if extType == 0x002b && len(extBody) >= 2 {
			sh.SelectedVersion = uint16(extBody[0])<<8 | uint16(extBody[1])
		}
		// ALPN(0x0010): structure is u16 list len, u8 proto len, proto bytes.
		if extType == 0x0010 && len(extBody) >= 3 {
			listLen := int(extBody[0])<<8 | int(extBody[1])
			if listLen+2 <= len(extBody) {
				protoLen := int(extBody[2])
				if 3+protoLen <= len(extBody) {
					sh.ALPN = string(extBody[3 : 3+protoLen])
				}
			}
		}
		off += thisLen
	}
	if sh.SelectedVersion == 0 {
		sh.SelectedVersion = sh.LegacyVersion
	}
	return sh, nil
}

// JA3SString computes the JA3S fingerprint pre-image of sh. Format:
// "SSLVersion,SelectedCipher,Extensions". Versions/ciphers/exts are
// decimal-encoded; extension list is hyphen-joined.
func JA3SString(sh *serverHello) string {
	if sh == nil {
		return ""
	}
	exts := make([]string, 0, len(sh.Extensions))
	for _, e := range sh.Extensions {
		exts = append(exts, fmt.Sprintf("%d", e))
	}
	return fmt.Sprintf("%d,%d,%s",
		sh.SelectedVersion, sh.SelectedCipher, strings.Join(exts, "-"))
}

// JA3SDigest returns the 32-char MD5 of JA3SString — the canonical
// 32-char form most tooling uses. MD5 is mandated by the JA3S spec.
func JA3SDigest(sh *serverHello) string {
	pre := JA3SString(sh)
	if pre == "" {
		return ""
	}
	sum := md5.Sum([]byte(pre)) //#nosec G401 -- JA3S spec
	return hex.EncodeToString(sum[:])
}

// JA4SString computes the JA4S fingerprint in FoxIO format:
//
//	t<ver><ext_count><alpn>_<cipher_hex>_<ext_hash>
//
// where ver is "13"/"12"/"11"/"10"/"s3" for TLS 1.3 / 1.2 / 1.1 / 1.0 / SSL3;
// ext_count is the two-digit count of extensions (capped at 99);
// alpn is the first/last alpn protocol characters (e.g. "h2", "h1", "00" if none);
// cipher_hex is the selected cipher in 4-char lowercase hex;
// ext_hash is the first 12 hex chars of SHA256 over the sorted comma-joined
// extension hex codes.
func JA4SString(sh *serverHello) string {
	if sh == nil {
		return ""
	}
	ver := ja4Version(sh.SelectedVersion)
	count := len(sh.Extensions)
	if count > 99 {
		count = 99
	}
	alpn := ja4ALPN(sh.ALPN)
	cipherHex := fmt.Sprintf("%04x", sh.SelectedCipher)
	extHash := ja4ExtensionsHash(sh.Extensions)
	return fmt.Sprintf("t%s%02d%s_%s_%s", ver, count, alpn, cipherHex, extHash)
}

// ja4Version maps a TLS uint16 version to FoxIO's 2-char field.
func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// ja4ALPN turns a negotiated ALPN protocol into the FoxIO 2-char
// abbreviation. Empty negotiation maps to "00".
func ja4ALPN(p string) string {
	switch {
	case p == "":
		return "00"
	case p == "h2":
		return "h2"
	case strings.HasPrefix(p, "http/1.1"):
		return "h1"
	case p == "h3":
		return "h3"
	case strings.HasPrefix(p, "grpc"):
		return "gr"
	}
	// Generic fallback: first + last printable byte.
	if len(p) == 1 {
		return p + p
	}
	return string(p[0]) + string(p[len(p)-1])
}

// ja4ExtensionsHash returns the first 12 hex chars of SHA256 over the
// sorted, comma-joined hex-encoded extension codes. The TLS 1.3 spec
// allows the same extension to appear at most once per message, but
// we de-duplicate anyway.
func ja4ExtensionsHash(exts []uint16) string {
	if len(exts) == 0 {
		return strings.Repeat("0", 12)
	}
	seen := make(map[uint16]struct{}, len(exts))
	out := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	parts := make([]string, len(out))
	for i, e := range out {
		parts[i] = fmt.Sprintf("%04x", e)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:6])
}
