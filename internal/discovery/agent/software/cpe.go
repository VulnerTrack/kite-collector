package software

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/sanitize"
)

// BuildCPE23 constructs a best-effort CPE 2.3 formatted string for an
// application. Fields that cannot be determined are set to "*" (ANY).
// Returns empty string when both product and version are empty.
func BuildCPE23(vendor, product, version string) string {
	return BuildCPE23Full(vendor, product, version, "", "")
}

// BuildCPE23WithArch constructs a CPE 2.3 string with an optional target
// hardware architecture in the target_hw field (position 10).
func BuildCPE23WithArch(vendor, product, version, arch string) string {
	return BuildCPE23Full(vendor, product, version, "", arch)
}

// BuildCPE23WithTargetSW constructs a CPE 2.3 string with a target software
// platform in the target_sw field (position 9). Used for language-specific
// packages (e.g. "python" for pip, "node.js" for npm).
func BuildCPE23WithTargetSW(vendor, product, version, targetSW string) string {
	return BuildCPE23Full(vendor, product, version, targetSW, "")
}

// BuildCPE23Full constructs a CPE 2.3 string with optional target_sw and
// target_hw fields.
func BuildCPE23Full(vendor, product, version, targetSW, targetHW string) string {
	p := normalizeComponent(product)
	v := normalizeVersion(version)

	if p == "" && v == "" {
		return ""
	}

	ven := normalizeComponent(vendor)
	if ven == "" {
		ven = "*"
	}
	if p == "" {
		p = "*"
	}
	if v == "" {
		v = "*"
	}

	tsw := "*"
	if s := normalizeComponent(targetSW); s != "" {
		tsw = s
	}

	thw := "*"
	if a := normalizeComponent(targetHW); a != "" {
		thw = a
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:%s:%s:*", ven, p, v, tsw, thw)
}

// normalizeComponent lowercases and sanitises a single CPE component value
// for the CPE 2.3 formatted-string binding. Accented letters fold to their
// ASCII base (café → cafe) so components stay inside the spec's ASCII
// grammar and matchable against the NVD dictionary; spaces become
// underscores (NVD's http_server convention); the unreserved characters
// [a-z0-9_.-] pass through bare; identity-bearing punctuation the spec
// requires quoting — "+" and "~" — is escaped (notepad++ → notepad\+\+,
// matching how NVD stores it) rather than deleted; everything else,
// including any remaining non-ASCII, is removed.
func normalizeComponent(s string) string {
	s = strings.ToLower(sanitize.Transliterate(strings.TrimSpace(s)))
	s = strings.ReplaceAll(s, " ", "_")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
			b.WriteRune(r)
		case r == '+' || r == '~':
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}

// epochPrefix matches the Debian/Arch epoch in a package version ("1:" in
// "1:29.7.1-1").
var epochPrefix = regexp.MustCompile(`^[0-9]+:`)

// normalizeVersion prepares a package-manager version string for the CPE
// version component: the epoch prefix is split off before normalization —
// NVD versions never carry epochs, and deleting the colon instead would
// fuse the epoch digit into the version (1:29.7.1 → 129.7.1). The distro
// release suffix (the -1 in 29.7.1-1) is deliberately kept: stripping it
// is ecosystem-specific knowledge that belongs to the collectors, a
// matching-fidelity question rather than an alphabet bug.
func normalizeVersion(s string) string {
	return normalizeComponent(epochPrefix.ReplaceAllString(strings.TrimSpace(s), ""))
}
