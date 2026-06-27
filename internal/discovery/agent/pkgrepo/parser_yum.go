package pkgrepo

import "strings"

// ParseYumRepo walks an /etc/yum.repos.d/*.repo file (also used by
// dnf and zypper). Grammar is INI:
//
//	[my-repo]
//	name=Description
//	baseurl=https://example.com/path
//	enabled=1
//	gpgcheck=1
//	gpgkey=file:///etc/pki/...
//	metalink=https://mirrors.fedoraproject.org/metalink?repo=...
//	mirrorlist=http://mirrorlist.centos.org/?release=...
//
// Each `[section]` becomes one Repo. baseurl/metalink/mirrorlist all
// supply URL — we prefer baseurl, fall back to metalink, then
// mirrorlist. `ecosystem` is passed in so the same parser serves
// yum/dnf/zypper without duplication.
func ParseYumRepo(raw []byte, filePath string, ecosystem Ecosystem) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		out     []Repo
		section string
		current map[string]string
	)
	flush := func() {
		if section == "" || current == nil {
			return
		}
		r := buildYumRepo(section, current, ecosystem, filePath, hash)
		if r.URL != "" {
			AnnotateSecurity(&r)
			out = append(out, r)
		}
		current = nil
		section = ""
	}

	for _, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			flush()
			section = strings.Trim(clean, "[]")
			current = make(map[string]string)
			continue
		}
		if current == nil {
			continue
		}
		k, v, ok := splitKV(clean)
		if !ok {
			continue
		}
		current[strings.ToLower(k)] = v
	}
	flush()

	if len(out) > MaxRepos {
		out = out[:MaxRepos]
	}
	return out
}

func buildYumRepo(name string, kv map[string]string, ecosystem Ecosystem, filePath, hash string) Repo {
	r := Repo{
		Ecosystem: ecosystem,
		Name:      name,
		FilePath:  filePath,
		FileHash:  hash,
	}
	// URL preference: baseurl > metalink > mirrorlist.
	switch {
	case kv["baseurl"] != "":
		r.URL = firstField(kv["baseurl"])
	case kv["metalink"] != "":
		r.URL = firstField(kv["metalink"])
	case kv["mirrorlist"] != "":
		r.URL = firstField(kv["mirrorlist"])
	}
	if v, ok := kv["enabled"]; ok {
		r.IsEnabled = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	} else {
		// Default in yum/dnf is enabled when the file is present.
		r.IsEnabled = true
	}
	r.GPGCheck = true
	if v, ok := kv["gpgcheck"]; ok {
		r.GPGCheck = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v, ok := kv["gpgkey"]; ok {
		r.SignedBy = firstField(v)
	}
	return r
}

// firstField returns the first whitespace-separated token of a value.
// yum/dnf accept multiple baseurls separated by whitespace; the audit
// flags the first as canonical.
func firstField(v string) string {
	fields := strings.Fields(strings.TrimSpace(v))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// ParseAPKRepositories walks /etc/apk/repositories — Alpine's flat
// list. Each non-comment line is a URL (or "@tag URL"). We treat each
// URL as one Repo, with the tag in Name when present.
func ParseAPKRepositories(raw []byte, filePath string) []Repo {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Repo, 0, len(lines))
	for i, line := range lines {
		clean := stripHashComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		r := Repo{
			Ecosystem: EcosystemAPK,
			IsEnabled: true,
			GPGCheck:  true, // apk verifies signatures by default
			FilePath:  filePath,
			FileHash:  hash,
			LineNo:    i + 1,
			RawLine:   clean,
		}
		// "@tag URL" form.
		if strings.HasPrefix(clean, "@") {
			fields := strings.Fields(clean)
			if len(fields) < 2 {
				continue
			}
			r.Name = strings.TrimPrefix(fields[0], "@")
			r.URL = fields[1]
		} else {
			r.URL = clean
			r.Name = "default"
		}
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxRepos {
			break
		}
	}
	return out
}
