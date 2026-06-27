package winauthkeys

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseAuthorizedKeys walks an authorized_keys body and returns
// one Key per non-comment, non-blank line. The grammar (sshd_config(5)
// AUTHORIZED_KEYS_FILE FORMAT):
//
//	[options] keytype base64-key [comment]
//
// `options` is comma-separated, MAY contain commas inside quoted
// strings (e.g. `command="ssh-shell --arg \"value\""`). When
// options are present they precede the keytype with no separator
// beyond whitespace.
func ParseAuthorizedKeys(body []byte, filePath string, scope KeyScope, user string) []Key {
	hash := HashContents(body)
	out := make([]Key, 0, 4)

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	lineNo := 0
	for scan.Scan() {
		lineNo++
		raw := scan.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k, ok := parseKeyLine(trimmed)
		if !ok {
			continue
		}
		k.FilePath = filePath
		k.FileHash = hash
		k.LineNo = lineNo
		k.UserProfile = user
		k.KeyScope = scope
		k.KeyType = NormalizeKeyType(k.KeyTypeRaw)
		k.KeyFingerprint = FingerprintKey(extractKeyBlob(trimmed))
		if k.KeyType == KeyTypeRSA || k.KeyType == KeyTypeRSASHA2 {
			k.KeyBits = ExtractRSABits(extractKeyBlob(trimmed))
		}
		AnnotateSecurity(&k)
		out = append(out, k)
		if len(out) >= MaxKeys {
			break
		}
	}
	return out
}

// parseKeyLine extracts the (options, keytype, comment) triple
// from a single authorized_keys line. Returns ok=false when the
// line doesn't carry at least a keytype + base64 blob.
//
// We use a heuristic split rather than a state-machine: find the
// first known key-type token; everything before it is options,
// everything after is `blob [comment]`.
func parseKeyLine(line string) (Key, bool) {
	idx, raw := findKeyTypeToken(line)
	if idx < 0 {
		return Key{}, false
	}
	options := strings.TrimSpace(line[:idx])
	// Strip any trailing whitespace + the matched keytype token.
	rest := strings.TrimSpace(line[idx+len(raw):])
	// rest should start with the base64 blob; comment follows
	// after the first whitespace.
	blob, comment := splitOnFirstSpace(rest)
	if blob == "" {
		return Key{}, false
	}
	return Key{
		KeyTypeRaw: raw,
		Comment:    strings.TrimSpace(comment),
		Options:    options,
	}, true
}

// findKeyTypeToken scans `line` for the first whitespace-
// delimited token matching one of the known SSH key-type
// prefixes. Returns the start offset and the matched token, or
// -1, "" when none is found.
func findKeyTypeToken(line string) (int, string) {
	// Walk word boundaries.
	start := 0
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ' ' || line[i] == '\t' {
			tok := line[start:i]
			if isKeyTypeToken(tok) {
				return start, tok
			}
			start = i + 1
		}
	}
	return -1, ""
}

// isKeyTypeToken reports whether `tok` matches a recognised SSH
// key-type identifier.
func isKeyTypeToken(tok string) bool {
	if tok == "" {
		return false
	}
	t := strings.ToLower(tok)
	switch t {
	case "ssh-rsa", "ssh-dss", "ssh-ed25519",
		"sk-ssh-ed25519@openssh.com":
		return true
	}
	switch {
	case strings.HasPrefix(t, "ecdsa-sha2-"),
		strings.HasPrefix(t, "sk-ecdsa-sha2-"),
		strings.HasPrefix(t, "rsa-sha2-"):
		return true
	}
	return false
}

// extractKeyBlob returns just the base64 blob portion of a key
// line. Used so the fingerprint + RSA-bits helpers don't need to
// re-parse the line.
func extractKeyBlob(line string) string {
	idx, raw := findKeyTypeToken(line)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len(raw):])
	blob, _ := splitOnFirstSpace(rest)
	return blob
}

// splitOnFirstSpace returns (head, tail) where head is the
// prefix up to (but not including) the first whitespace, and
// tail is the trimmed remainder.
func splitOnFirstSpace(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], strings.TrimSpace(s[i+1:])
		}
	}
	return s, ""
}
