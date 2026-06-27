package pkgrepo

import "strings"

// ParseAPTSourcesList walks the legacy /etc/apt/sources.list (or any
// file under /etc/apt/sources.list.d/*.list). Grammar per sources.list(5):
//
//	deb     [options] uri distribution components
//	deb-src [options] uri distribution components
//
// `options` is a space-separated `key=value` list inside `[...]`, where
// `signed-by=/path/to/key.gpg` and `trusted=yes` are the security-relevant
// keys. We surface signed-by via SignedBy, and `trusted=yes` flips
// GPGCheck off (because it skips signature checking).
func ParseAPTSourcesList(raw []byte, filePath string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Repo, 0, 8)
	for i, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		r, ok := parseAPTLine(clean)
		if !ok {
			continue
		}
		r.FilePath = filePath
		r.FileHash = hash
		r.LineNo = i + 1
		r.RawLine = clean
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxRepos {
			break
		}
	}
	return out
}

// parseAPTLine handles one `deb` / `deb-src` line, including the
// bracketed options syntax.
func parseAPTLine(line string) (Repo, bool) {
	r := Repo{
		Ecosystem: EcosystemAPT,
		IsEnabled: true,
		GPGCheck:  true, // APT defaults to gpg-check unless trusted=yes
		Name:      "default",
	}
	switch {
	case strings.HasPrefix(line, "deb "), strings.HasPrefix(line, "deb\t"):
		r.IsSource = false
		line = strings.TrimSpace(line[len("deb"):])
	case strings.HasPrefix(line, "deb-src "), strings.HasPrefix(line, "deb-src\t"):
		r.IsSource = true
		line = strings.TrimSpace(line[len("deb-src"):])
	default:
		return Repo{}, false
	}
	// Optional [options] block.
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 0 {
			return Repo{}, false
		}
		opts := line[1:end]
		for _, kv := range strings.Fields(opts) {
			k, v, ok := splitKV(kv)
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "signed-by":
				r.SignedBy = v
			case "trusted":
				if strings.EqualFold(v, "yes") {
					r.GPGCheck = false
				}
			case "arch":
				r.Architectures = strings.Split(v, ",")
			}
		}
		line = strings.TrimSpace(line[end+1:])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Repo{}, false
	}
	r.URL = fields[0]
	r.Distribution = fields[1]
	if len(fields) > 2 {
		r.Components = append([]string(nil), fields[2:]...)
	}
	// Pretty name = host + dist for stable diff/dedup keys.
	if host := hostOf(r.URL); host != "" {
		r.Name = host + " " + r.Distribution
	}
	return r, true
}

// ParseAPTDeb822 walks an /etc/apt/sources.list.d/*.sources file.
// The deb822 format is paragraph-based; each paragraph maps to one
// Repo (or many if URIs/Suites contain multiple tokens — but we
// emit one row per paragraph for simplicity).
//
//	Types: deb deb-src
//	URIs: http://archive.ubuntu.com/ubuntu
//	Suites: noble noble-updates noble-backports
//	Components: main restricted universe multiverse
//	Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
//	Enabled: yes
//	Trusted: yes
func ParseAPTDeb822(raw []byte, filePath string) []Repo {
	hash := HashContents(raw)
	paragraphs := splitParagraphs(raw)

	out := make([]Repo, 0, len(paragraphs))
	for i, paragraph := range paragraphs {
		fields := parseDeb822Fields(paragraph)
		if len(fields) == 0 {
			continue
		}
		r := Repo{
			Ecosystem: EcosystemAPT,
			IsEnabled: true,
			GPGCheck:  true,
			FilePath:  filePath,
			FileHash:  hash,
			LineNo:    i + 1, // paragraph index, 1-based
		}
		if v, ok := fields["types"]; ok {
			r.IsSource = strings.Contains(v, "deb-src")
		}
		if v, ok := fields["uris"]; ok {
			parts := strings.Fields(v)
			if len(parts) > 0 {
				r.URL = parts[0] // primary URL
			}
		}
		if v, ok := fields["suites"]; ok {
			parts := strings.Fields(v)
			if len(parts) > 0 {
				r.Distribution = parts[0]
			}
		}
		if v, ok := fields["components"]; ok {
			r.Components = strings.Fields(v)
		}
		if v, ok := fields["architectures"]; ok {
			r.Architectures = strings.Fields(v)
		}
		if v, ok := fields["signed-by"]; ok {
			r.SignedBy = strings.TrimSpace(v)
		}
		if v, ok := fields["enabled"]; ok {
			r.IsEnabled = !strings.EqualFold(strings.TrimSpace(v), "no")
		}
		if v, ok := fields["trusted"]; ok && strings.EqualFold(strings.TrimSpace(v), "yes") {
			r.GPGCheck = false
		}
		if r.URL == "" {
			continue
		}
		if host := hostOf(r.URL); host != "" {
			r.Name = host + " " + r.Distribution
		}
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxRepos {
			break
		}
	}
	return out
}

// parseDeb822Fields walks one paragraph and returns lowercase field keys.
// Continuation lines (RFC822-style starting with whitespace) are folded
// into the preceding field.
func parseDeb822Fields(paragraph string) map[string]string {
	out := map[string]string{}
	var lastKey string
	for _, line := range strings.Split(paragraph, "\n") {
		if line == "" {
			continue
		}
		if line[0] == '#' {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey != "" {
				out[lastKey] = out[lastKey] + " " + strings.TrimSpace(line)
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		out[key] = val
		lastKey = key
	}
	return out
}

// splitParagraphs splits a deb822 body on blank-line boundaries.
func splitParagraphs(raw []byte) []string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	parts := strings.Split(text, "\n\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}
