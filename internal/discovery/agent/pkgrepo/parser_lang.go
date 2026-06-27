package pkgrepo

import (
	"strings"
)

// ParsePipConfig walks ~/.config/pip/pip.conf or /etc/pip.conf.
// Grammar is INI-with-comments. Relevant keys are `index-url`
// (primary), `extra-index-url` (one per line or whitespace-separated),
// and `trusted-host` (which disables TLS validation per host — a
// CWE-345 flag).
func ParsePipConfig(raw []byte, filePath, userScope string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		section      string
		indexURL     string
		extraIndex   []string
		trustedHosts []string
	)
	for _, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			section = strings.ToLower(strings.Trim(clean, "[]"))
			continue
		}
		if section != "global" && section != "install" && section != "" {
			continue
		}
		k, v, ok := splitKV(clean)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "index-url", "index_url":
			indexURL = strings.TrimSpace(v)
		case "extra-index-url", "extra_index_url":
			extraIndex = append(extraIndex, strings.Fields(v)...)
		case "trusted-host", "trusted_host":
			trustedHosts = append(trustedHosts, strings.Fields(v)...)
		}
	}

	var out []Repo
	if indexURL != "" {
		out = append(out, mkPip(indexURL, "primary", trustedHosts, userScope, filePath, hash))
	}
	for _, u := range extraIndex {
		out = append(out, mkPip(u, "extra", trustedHosts, userScope, filePath, hash))
	}
	return out
}

func mkPip(rawURL, name string, trustedHosts []string, userScope, filePath, hash string) Repo {
	r := Repo{
		Ecosystem: EcosystemPip,
		Name:      name,
		URL:       rawURL,
		IsEnabled: true,
		GPGCheck:  true, // pip checks TLS by default; trusted-host disables it
		UserScope: userScope,
		FilePath:  filePath,
		FileHash:  hash,
	}
	host := hostOf(rawURL)
	for _, t := range trustedHosts {
		if strings.EqualFold(t, host) {
			r.GPGCheck = false
		}
	}
	AnnotateSecurity(&r)
	return r
}

// ParseNPMrc walks ~/.npmrc or /etc/npmrc. Relevant keys are `registry`
// (default) and any `@scope:registry=...` per-scope override. We emit
// one Repo per registry URL.
func ParseNPMrc(raw []byte, filePath, userScope string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var out []Repo
	for _, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		k, v, ok := splitKV(clean)
		if !ok {
			continue
		}
		name := ""
		switch {
		case strings.EqualFold(k, "registry"):
			name = "default"
		case strings.HasSuffix(strings.ToLower(k), ":registry"):
			name = strings.TrimSuffix(k, ":registry")
		default:
			continue
		}
		v = strings.TrimSpace(strings.Trim(v, `"`))
		r := Repo{
			Ecosystem: EcosystemNPM,
			Name:      name,
			URL:       v,
			IsEnabled: true,
			GPGCheck:  true,
			UserScope: userScope,
			FilePath:  filePath,
			FileHash:  hash,
		}
		AnnotateSecurity(&r)
		out = append(out, r)
	}
	return out
}

// ParseCargoConfig walks ~/.cargo/config.toml. We don't pull in a full
// TOML parser — only the very narrow `[source.<name>] registry = "..."`
// shape we care about. Falls back gracefully on anything more complex.
func ParseCargoConfig(raw []byte, filePath, userScope string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		out      []Repo
		section  string
		sourceID string
	)
	for _, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			section = strings.ToLower(strings.Trim(clean, "[]"))
			if strings.HasPrefix(section, "source.") {
				sourceID = strings.TrimPrefix(section, "source.")
				sourceID = strings.Trim(sourceID, "\"")
			} else {
				sourceID = ""
			}
			continue
		}
		if sourceID == "" {
			continue
		}
		k, v, ok := splitKV(clean)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), "registry") {
			continue
		}
		url := strings.Trim(strings.TrimSpace(v), `"`)
		if url == "" {
			continue
		}
		r := Repo{
			Ecosystem: EcosystemCargo,
			Name:      sourceID,
			URL:       url,
			IsEnabled: true,
			GPGCheck:  true,
			UserScope: userScope,
			FilePath:  filePath,
			FileHash:  hash,
		}
		AnnotateSecurity(&r)
		out = append(out, r)
	}
	return out
}

// ParseGemrc walks ~/.gemrc. Relevant key is `:sources:` followed by
// a YAML list. We accept only the inline-list shape (`:sources: [a,b]`)
// and the dashed block shape — anything more elaborate falls through.
func ParseGemrc(raw []byte, filePath, userScope string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		inBlock bool
		sources []string
	)
	for _, line := range lines {
		rawLine := line
		clean := stripHashComment(rawLine)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, ":sources:") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, ":sources:"))
			if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
				rest = strings.Trim(rest, "[]")
				for _, s := range strings.Split(rest, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						sources = append(sources, s)
					}
				}
				inBlock = false
				continue
			}
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") {
			inBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "-") {
			sources = append(sources, strings.TrimSpace(trimmed[1:]))
		}
	}
	out := make([]Repo, 0, len(sources))
	for _, s := range sources {
		r := Repo{
			Ecosystem: EcosystemGem,
			Name:      "default",
			URL:       s,
			IsEnabled: true,
			GPGCheck:  true,
			UserScope: userScope,
			FilePath:  filePath,
			FileHash:  hash,
		}
		AnnotateSecurity(&r)
		out = append(out, r)
	}
	return out
}
