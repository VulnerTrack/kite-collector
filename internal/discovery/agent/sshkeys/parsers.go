package sshkeys

import (
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
)

// ParseAuthorizedKeysLine parses a single line of authorized_keys /
// known_hosts in the OpenSSH AUTHORIZED_KEYS FILE FORMAT (sshd(8)).
//
// Optional leading `options` (comma-separated, may contain spaces inside
// double-quoted strings) precedes the key_type. Key line shape:
//
//	[options] <key_type> <base64-blob> [comment]
//
// known_hosts uses a slightly different shape:
//
//	<hostname-or-pattern>[,ip] <key_type> <base64-blob> [comment]
//
// Hashed known_hosts lines start with `|1|` — we keep them but mark
// hostname as "HASHED" since we can't recover the plaintext.
//
// Returns ok=false when:
//   - The line is empty or a comment.
//   - We can't find the trio (key_type, base64-blob).
//   - The base64 blob fails to decode.
//   - The blob's embedded key_type doesn't match the line's key_type
//     (defends against malformed/forged entries).
func ParseAuthorizedKeysLine(line string) (keyType, base64Blob, comment, options string, blob []byte, ok bool) {
	line = trim(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", nil, false
	}

	rest := line
	// Detect a leading options block. Options are present when the first
	// token is NOT a known key_type prefix. The cheap heuristic: if the
	// first whitespace-delimited token starts with one of the known
	// algorithm prefixes, there are no options; otherwise consume up to
	// the first non-quoted space.
	if !looksLikeAlgo(firstToken(rest)) {
		// Walk forward respecting double-quoted strings.
		split := splitOptionsAndRest(rest)
		options = split[0]
		rest = split[1]
		if rest == "" {
			return "", "", "", "", nil, false
		}
	}

	fields := strings.SplitN(rest, " ", 3)
	if len(fields) < 2 {
		return "", "", "", "", nil, false
	}
	keyType = fields[0]
	base64Blob = strings.TrimSpace(fields[1])
	if len(fields) == 3 {
		comment = strings.TrimSpace(fields[2])
	}

	decoded, err := base64.StdEncoding.DecodeString(base64Blob)
	if err != nil {
		return "", "", "", "", nil, false
	}
	embedded, ok := readSSHString(decoded)
	if !ok {
		return "", "", "", "", nil, false
	}
	if string(embedded) != keyType {
		return "", "", "", "", nil, false
	}
	return keyType, base64Blob, comment, options, decoded, true
}

// ParseKnownHostsLine parses one known_hosts line, returning the
// hostname pattern (or "HASHED" for |1| lines) plus the same fields
// that AuthorizedKeysLine produces. ok=false on empty/comment lines.
func ParseKnownHostsLine(line string) (hostname, keyType, base64Blob, comment string, blob []byte, ok bool) {
	line = trim(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", nil, false
	}

	fields := strings.SplitN(line, " ", 4)
	if len(fields) < 3 {
		return "", "", "", "", nil, false
	}
	hostname = fields[0]
	keyType = fields[1]
	base64Blob = fields[2]
	if len(fields) == 4 {
		comment = strings.TrimSpace(fields[3])
	}
	if strings.HasPrefix(hostname, "|1|") {
		hostname = "HASHED"
	}
	decoded, err := base64.StdEncoding.DecodeString(base64Blob)
	if err != nil {
		return "", "", "", "", nil, false
	}
	embedded, ok := readSSHString(decoded)
	if !ok || string(embedded) != keyType {
		return "", "", "", "", nil, false
	}
	return hostname, keyType, base64Blob, comment, decoded, true
}

// KeyBitsFromBlob returns the key size in bits for RSA / DSA / ECDSA
// keys, or 0 for fixed-size algorithms (ed25519, sk-ed25519@openssh).
// The blob is the binary-decoded public key (after base64 unwrap),
// matching what FingerprintBlob takes.
//
// SSH wire format for a public key blob is a series of length-prefixed
// (uint32 big-endian) strings:
//
//	ssh-rsa:   "ssh-rsa", e, n   →   bits = bitlen(n)
//	ssh-dss:   "ssh-dss", p, q, g, y  →  bits = bitlen(p)
//	ecdsa-…:   "ecdsa-…", curve, Q   →   bits inferred from curve name
//	ssh-ed25519: "ssh-ed25519", k    →   fixed 256 bits
func KeyBitsFromBlob(blob []byte) int {
	keyType, rest, ok := splitSSHString(blob)
	if !ok {
		return 0
	}
	switch string(keyType) {
	case "ssh-rsa":
		// Skip exponent e, read modulus n.
		_, rest, ok = splitSSHString(rest)
		if !ok {
			return 0
		}
		n, _, ok := splitSSHString(rest)
		if !ok {
			return 0
		}
		return new(big.Int).SetBytes(n).BitLen()
	case "ssh-dss":
		p, _, ok := splitSSHString(rest)
		if !ok {
			return 0
		}
		return new(big.Int).SetBytes(p).BitLen()
	case "ecdsa-sha2-nistp256":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		return 256
	}
	return 0
}

// PrivateKeyHasPassphrase inspects an OpenSSH private-key file body
// and returns true when the embedded encryption marker indicates the
// key is passphrase-protected.
//
// Detection rules per format:
//
//   - OpenSSH v1 format ("-----BEGIN OPENSSH PRIVATE KEY-----"): the
//     base64 body decodes to "openssh-key-v1\x00" + cipher name. When
//     cipher == "none" the key is unprotected; anything else means a
//     passphrase was used.
//   - Legacy PEM ("-----BEGIN RSA PRIVATE KEY-----" etc.): unprotected
//     when the PEM body does NOT contain a "Proc-Type: 4,ENCRYPTED"
//     header. Encrypted PEM keys carry "DEK-Info: <cipher>,…" and the
//     Proc-Type header.
//
// Returns (false, false) when format detection fails — caller treats
// "unknown" as "unprotected" for the conservative audit posture.
func PrivateKeyHasPassphrase(raw []byte) (has bool, recognised bool) {
	text := string(raw)
	switch {
	case strings.Contains(text, "BEGIN OPENSSH PRIVATE KEY"):
		body := extractPEMBody(text, "OPENSSH PRIVATE KEY")
		if body == "" {
			return false, false
		}
		decoded, err := base64.StdEncoding.DecodeString(stripWhitespace(body))
		if err != nil {
			return false, false
		}
		const magic = "openssh-key-v1\x00"
		if !strings.HasPrefix(string(decoded), magic) {
			return false, false
		}
		// After the magic string comes the cipher name as an SSH string.
		cipher, _, ok := splitSSHString(decoded[len(magic):])
		if !ok {
			return false, true
		}
		return string(cipher) != "none", true
	case strings.Contains(text, "BEGIN RSA PRIVATE KEY"),
		strings.Contains(text, "BEGIN DSA PRIVATE KEY"),
		strings.Contains(text, "BEGIN EC PRIVATE KEY"),
		strings.Contains(text, "BEGIN PRIVATE KEY"),
		strings.Contains(text, "BEGIN ENCRYPTED PRIVATE KEY"):
		if strings.Contains(text, "BEGIN ENCRYPTED PRIVATE KEY") {
			return true, true
		}
		if strings.Contains(text, "Proc-Type: 4,ENCRYPTED") ||
			strings.Contains(text, "DEK-Info:") {
			return true, true
		}
		return false, true
	}
	return false, false
}

// --- low-level helpers (no public surface) -------------------------------

// readSSHString returns the first length-prefixed SSH wire string in
// blob, or (nil, false) when the blob is truncated.
func readSSHString(blob []byte) ([]byte, bool) {
	s, _, ok := splitSSHString(blob)
	return s, ok
}

// splitSSHString returns (first-string, remaining-blob, ok).
func splitSSHString(blob []byte) ([]byte, []byte, bool) {
	if len(blob) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if uint64(n)+4 > uint64(len(blob)) {
		return nil, nil, false
	}
	return blob[4 : 4+n], blob[4+n:], true
}

// looksLikeAlgo reports whether a token looks like an SSH key-type
// prefix. The list is short and stable.
func looksLikeAlgo(tok string) bool {
	switch tok {
	case "ssh-rsa", "ssh-dss", "ssh-ed25519",
		"rsa-sha2-256", "rsa-sha2-512",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}

// firstToken returns the first whitespace-delimited token of s.
func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// splitOptionsAndRest splits an authorized_keys line on the first
// whitespace OUTSIDE a double-quoted region. Returns [options, rest].
func splitOptionsAndRest(line string) [2]string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if (c == ' ' || c == '\t') && !inQuote {
			return [2]string{trim(line[:i]), trim(line[i+1:])}
		}
	}
	return [2]string{line, ""}
}

// extractPEMBody returns the base64 body between a -----BEGIN <label>-----
// / -----END <label>----- pair. Whitespace inside the body is preserved
// — callers should strip it before base64-decoding.
func extractPEMBody(text, label string) string {
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
	i := strings.Index(text, begin)
	if i < 0 {
		return ""
	}
	j := strings.Index(text[i:], end)
	if j < 0 {
		return ""
	}
	body := text[i+len(begin) : i+j]
	// Strip header lines (Proc-Type, DEK-Info) before the body.
	if idx := strings.Index(body, "\n\n"); idx >= 0 {
		body = body[idx+2:]
	}
	return strings.TrimSpace(body)
}

func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
