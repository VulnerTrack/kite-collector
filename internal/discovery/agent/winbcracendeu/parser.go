package winbcracendeu

import (
	"bufio"
	"bytes"
	"strings"
)

// SnapshotStats captures the per-file aggregates the audit
// pipeline cares about, computed without re-storing rows.
type SnapshotStats struct {
	RecordCount          int
	DistinctEntityCount  int
	MaxSituacion         int
	HasChequesRechazados bool
}

// ParseCENDEUSnapshot streams the body line-by-line and
// derives the SnapshotStats. The format is unspecified at
// this layer — we run a tolerant scanner that:
//
//   - counts non-empty, non-comment lines as records,
//   - extracts 11-digit CUITs to derive distinct-entity count,
//   - extracts `situacion=N` or standalone single-digit tokens
//     in {1..6} preceded by a CUIT to derive the max
//     situación, and
//   - flags cheques-rechazados when the body references the
//     literal token.
//
// Returns zero-value stats on empty input.
func ParseCENDEUSnapshot(body []byte) SnapshotStats {
	var out SnapshotStats
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	seen := make(map[string]struct{}, 64)
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "cheque") &&
		(strings.Contains(lower, "rechaz") || strings.Contains(lower, "rch")) {
		out.HasChequesRechazados = true
	}

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)

	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		out.RecordCount++

		// Try explicit `situacion=N` form first.
		if m := SituacionRE.FindStringSubmatch(line); m != nil {
			n := digitToInt(firstNonEmpty(m[1], m[2]))
			if n > out.MaxSituacion {
				out.MaxSituacion = n
			}
		}

		// Extract CUIT-shaped runs and the immediately-following
		// 1-digit (1..6) token as situación fallback.
		extractCUITSituacion(line, seen, &out)
	}
	out.DistinctEntityCount = len(seen)
	return out
}

func extractCUITSituacion(line string, seen map[string]struct{}, out *SnapshotStats) {
	// Strip non-alphanumeric / non-CSV-separator chars to a
	// canonical run we can scan token-by-token.
	fields := splitFields(line)
	cuitSeen := false
	for _, f := range fields {
		digits := keepDigits(f)
		if len(digits) == 11 && IsValidCuitEntityPrefix(digits[:2]) {
			seen[digits] = struct{}{}
			cuitSeen = true
			continue
		}
		// After the CUIT, every single-digit field in {1..6} is a
		// situación candidate. We take the max so column-position
		// drift across BCRA's CSV variants doesn't break extraction.
		if cuitSeen {
			t := strings.TrimSpace(f)
			if len(t) == 1 && t[0] >= '1' && t[0] <= '6' {
				n := int(t[0] - '0')
				if n > out.MaxSituacion {
					out.MaxSituacion = n
				}
			}
		}
	}
}

// splitFields splits a line on whitespace, comma, semicolon,
// or tab — the union of separators BCRA snapshot files use.
func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', ',', ';', '|':
			return true
		}
		return false
	})
}

func keepDigits(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}

func digitToInt(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	if c < '0' || c > '9' {
		return 0
	}
	return int(c - '0')
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
