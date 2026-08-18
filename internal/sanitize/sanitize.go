// Package sanitize provides composable cleaning controls for strings
// ingested from external sources — package-manager CLI output, osquery
// rows, network banners, parsed config files. Every discovery surface
// ultimately shells out to or parses tools kite does not control; these
// controls keep mojibake, ANSI decorations, and invisible Unicode out of
// persisted inventory fields.
//
// Controls:
//
//  1. Trim           — strip leading/trailing whitespace.
//  2. Subset         — restrict to an allowed rune subset (lossy, opt-in);
//     Transliterate/ToASCII fold accents instead of dropping them.
//  3. FixEncoding    — repair non-UTF-8 input by decoding it as Latin-1.
//  4. StripInvisible — drop ANSI escape sequences plus control/format
//     runes, keeping whitespace.
//
// Clean composes the non-lossy controls (3 → 4 → 1) in the only order
// that is sound: encoding repair first so rune classification sees real
// code points, invisible removal second, trim last because removing
// invisible runes can expose fresh edge whitespace.
package sanitize

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Trim strips leading and trailing whitespace (control 1).
func Trim(s string) string { return strings.TrimSpace(s) }

// FixEncoding returns s unchanged when it is valid UTF-8; otherwise it
// reinterprets the bytes as Latin-1 (ISO 8859-1) and re-encodes them as
// UTF-8 (control 3). Latin-1 maps every byte to the code point of the
// same value, so the conversion is total: genuinely non-Latin-1 input can
// come out garbled, but the result is always valid UTF-8, which beats
// persisting bytes that render as replacement characters downstream.
func FixEncoding(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	runes := make([]rune, 0, len(s))
	for i := 0; i < len(s); i++ {
		runes = append(runes, rune(s[i]))
	}
	return string(runes)
}

// ansiSequences matches ANSI escape sequences: CSI (colors, cursor
// movement), OSC (terminal titles, hyperlinks; BEL- or ST-terminated),
// and the remaining two-byte Fe escapes. Tools like yay keep these
// decorations even when stdout is a pipe.
var ansiSequences = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])`)

// StripANSI removes ANSI escape sequences. Exposed separately from
// StripInvisible for parsers that must strip decorations before
// line-splitting (see the yay collector).
func StripANSI(s string) string { return ansiSequences.ReplaceAllString(s, "") }

// StripInvisible removes ANSI escape sequences, control runes (Cc), and
// invisible format runes (Cf: zero-width spaces and joiners, BOMs, bidi
// overrides, soft hyphens) while keeping every whitespace rune — tab,
// newline, carriage return, space, and the Unicode space separators
// (control 4). Stray invalid-UTF-8 bytes and replacement characters are
// dropped too; run FixEncoding first when the source may be Latin-1 so
// they are repaired instead.
func StripInvisible(s string) string {
	s = StripANSI(s)
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return r
		case unicode.In(r, unicode.Cc, unicode.Cf), r == utf8.RuneError:
			return -1
		default:
			return r
		}
	}, s)
}

// Alphabet reports whether a rune belongs to an allowed subset.
type Alphabet func(rune) bool

// Subset removes every rune the alphabet does not allow (control 2). This
// is the lossy control: apply it after Clean, and only to fields with a
// known shape — an identifier, not free text.
func Subset(s string, allow Alphabet) string {
	return strings.Map(func(r rune) rune {
		if allow(r) {
			return r
		}
		return -1
	}, s)
}

// Transliterate folds accented Latin characters to their base form by
// decomposing to NFD and dropping the combining marks (Mn): "café" →
// "cafe", "España" → "Espana". Runes with no decomposition (emoji, CJK,
// ø) pass through unchanged — pair with Subset to enforce an alphabet.
func Transliterate(s string) string {
	stripped := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, norm.NFD.String(s))
	return norm.NFC.String(stripped)
}

// ToASCII is the aggressive lossy pipeline for fields that must end up
// plain ASCII: transliterate accents, drop everything outside printable
// ASCII, then collapse and trim the whitespace runs the removals leave
// behind — "café ☕" becomes "cafe", not "caf ".
func ToASCII(s string) string {
	return strings.Join(strings.Fields(Subset(Transliterate(s), ASCIIPrintable)), " ")
}

// ASCIIPrintable allows the printable ASCII range, space through tilde.
func ASCIIPrintable(r rune) bool { return r >= 0x20 && r <= 0x7e }

// PackageIdentifier allows the characters that appear in well-formed
// package names and versions across the supported ecosystems: ASCII
// letters and digits plus . _ - + : ~ @ /  (epoch colons, Debian tilde
// revisions, scoped npm names, nested Go module paths).
func PackageIdentifier(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("._-+:~@/", r)
}

// Clean applies the standard non-lossy pipeline for text captured from
// untrusted tool output: FixEncoding, then StripInvisible, then Trim.
func Clean(s string) string { return Trim(StripInvisible(FixEncoding(s))) }
