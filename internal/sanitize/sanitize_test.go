package sanitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrim(t *testing.T) {
	assert.Equal(t, "curl 8.9.1", Trim("  curl 8.9.1\t\n"))
	assert.Equal(t, "", Trim(" \t\r\n "))
}

func TestFixEncoding(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"valid utf-8 untouched", "openssl 3.3.1", "openssl 3.3.1"},
		{"valid multibyte untouched", "café ☕", "café ☕"},
		{"latin-1 e-acute repaired", "Caf\xe9", "Café"},
		{"latin-1 n-tilde repaired", "Espa\xf1a", "España"},
		{"latin-1 copyright repaired", "\xa9 2026", "© 2026"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FixEncoding(tt.in))
		})
	}
}

func TestStripANSI(t *testing.T) {
	// Exact bytes yay emits when run as root.
	assert.Equal(t, " -> Avoid running yay as root/sudo.",
		StripANSI("\x1b[1m\x1b[33m -> \x1b[0m\x1b[0mAvoid running yay as root/sudo."))
	// OSC hyperlink (BEL-terminated) and a bare Fe escape.
	assert.Equal(t, "linktext", StripANSI("\x1b]8;;https://x\x07link\x1b]8;;\x07text"))
	assert.Equal(t, "ab", StripANSI("a\x1bMb"))
}

func TestStripInvisible(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"zero-width space dropped", "python\u200b3", "python3"},
		{"zwj and zwnj dropped", "a\u200d\u200cb", "ab"},
		{"bom dropped", "\ufeffnginx", "nginx"},
		{"bidi override dropped", "\u202eexe.bat", "exe.bat"},
		{"soft hyphen dropped", "long\u00adname", "longname"},
		{"nul and bell dropped", "a\x00b\x07c", "abc"},
		{"ansi colors dropped", "\x1b[32mok\x1b[0m", "ok"},
		{"tabs newlines kept", "a\tb\nc", "a\tb\nc"},
		{"nbsp kept as whitespace", "a\u00a0b", "a\u00a0b"},
		{"replacement char dropped", "bad\ufffdbyte", "badbyte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, StripInvisible(tt.in))
		})
	}
}

func TestSubset(t *testing.T) {
	assert.Equal(t, "libfoo2.1", Subset("libfoo (2.1)", PackageIdentifier))
	assert.Equal(t, "@scope/pkg", Subset("@scope/pkg", PackageIdentifier))
	assert.Equal(t, "1:2.4-1~bpo", Subset("1:2.4-1~bpo", PackageIdentifier))
	// Subset alone filters (é dropped); ToASCII transliterates instead.
	assert.Equal(t, "caf ", Subset("café ☕", ASCIIPrintable))
}

func TestClean_ComposedPipeline(t *testing.T) {
	// Latin-1 bytes + ANSI decoration + a NUL + edge whitespace in one
	// value: encoding repaired first, invisibles dropped, then trimmed --
	// interior whitespace preserved.
	in := " \x1b[1mCaf\xe9 Bar\x00 \t"
	assert.Equal(t, "Café Bar", Clean(in))
	// Result is always valid UTF-8 even for garbage input.
	assert.Equal(t, "ÿ", Clean("\xff"))
}

func TestTransliterate(t *testing.T) {
	assert.Equal(t, "cafe", Transliterate("café"))
	assert.Equal(t, "Espana", Transliterate("España"))
	assert.Equal(t, "Zurich ☕", Transliterate("Zürich ☕"))
}

func TestToASCII(t *testing.T) {
	assert.Equal(t, "cafe", ToASCII("café ☕"))
	assert.Equal(t, "Uber 2.0", ToASCII("Über  2.0"))
	assert.Equal(t, "", ToASCII("☕"))
}
