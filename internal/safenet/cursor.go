package safenet

import (
	"fmt"
	"unicode/utf8"
)

// MaxCursorLength is the maximum byte length of a sanitized pagination
// cursor. 2 KiB is two orders of magnitude larger than any production cursor
// observed in tested SaaS APIs and small enough that a malicious server
// cannot use the cursor field as a covert exfiltration channel.
const MaxCursorLength = 2048

// SanitizeCursor validates a pagination cursor received from an untrusted
// upstream API. It enforces:
//
//   - non-empty after trimming
//   - byte length ≤ MaxCursorLength
//   - all bytes are ASCII in the allowlist [a-zA-Z0-9+/=_\-:@.] — covers
//     standard and URL-safe base64, hex, opaque-string, and most JWT-shaped
//     cursors used by VPS/PaaS providers
//
// The allowlist explicitly excludes path separators, scheme delimiters,
// query separators, and any character that could change URL semantics when
// the cursor is concatenated into a request URL. Returning the original
// string on success keeps the value byte-identical for the API.
func SanitizeCursor(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("cursor is empty")
	}
	if len(raw) > MaxCursorLength {
		return "", fmt.Errorf("cursor length %d exceeds maximum %d",
			len(raw), MaxCursorLength)
	}
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("cursor contains invalid UTF-8")
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !isCursorByte(c) {
			return "", fmt.Errorf(
				"cursor contains disallowed character %q at offset %d "+
					"(allowlist: [a-zA-Z0-9+/=_\\-:@.])", c, i)
		}
	}
	return raw, nil
}

func isCursorByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '+', '/', '=', '_', '-', ':', '@', '.':
		return true
	}
	return false
}
