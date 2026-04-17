package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dependency holds a single package name, version, and its OSV ecosystem.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string // "Go", "npm", "PyPI", "crates.io", "Maven"
}

// CollectDependencies walks repoPath looking for known manifest files and
// returns all parseable dependencies. Errors on individual manifests are
// logged via the returned list's accompanying error slice so callers still
// get partial results.
func CollectDependencies(repoPath string) ([]Dependency, []error) {
	type manifest struct {
		parse func(string) ([]Dependency, error)
		name  string
	}

	manifests := []manifest{
		{parseGoMod, "go.mod"},
		{parsePackageJSON, "package.json"},
		{parseRequirementsTxt, "requirements.txt"},
		{parseCargoToml, "Cargo.toml"},
	}

	var (
		deps []Dependency
		errs []error
	)

	for _, m := range manifests {
		path := filepath.Join(repoPath, m.name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		found, err := m.parse(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.name, err))
			continue
		}
		deps = append(deps, found...)
	}

	return deps, errs
}

// parseGoMod extracts direct requirements from a go.mod file.
// It handles both single-line and block require directives.
func parseGoMod(path string) ([]Dependency, error) {
	f, err := os.Open(path) //#nosec G304 -- path is derived from user config
	if err != nil {
		return nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer func() { _ = f.Close() }()

	var deps []Dependency
	inRequireBlock := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Single-line: require github.com/foo/bar v1.2.3
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			if dep, ok := parseGoRequireLine(line); ok {
				deps = append(deps, dep)
			}
			continue
		}

		if inRequireBlock {
			if dep, ok := parseGoRequireLine(line); ok {
				deps = append(deps, dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go.mod: %w", err)
	}
	return deps, nil
}

func parseGoRequireLine(line string) (Dependency, bool) {
	// Strip inline comments: "github.com/foo/bar v1.2.3 // indirect"
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Dependency{}, false
	}
	return Dependency{
		Name:      parts[0],
		Version:   strings.TrimPrefix(parts[1], "v"),
		Ecosystem: "Go",
	}, true
}

// packageJSON is the subset of package.json we care about.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parsePackageJSON extracts npm dependencies from package.json.
func parsePackageJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	deps := make([]Dependency, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name, ver := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanNPMVersion(ver),
			Ecosystem: "npm",
		})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanNPMVersion(ver),
			Ecosystem: "npm",
		})
	}
	return deps, nil
}

// cleanNPMVersion strips npm version range prefixes (^, ~, >=, <=, >, <, =)
// so that OSV receives a plain semver like "4.17.10".
func cleanNPMVersion(ver string) string {
	return strings.TrimLeft(ver, "^~>=< ")
}

// parseRequirementsTxt extracts pinned dependencies from requirements.txt.
// Only lines with an exact version specifier (==) are used; unpinned lines
// are skipped because OSV needs an explicit version to query.
func parseRequirementsTxt(path string) ([]Dependency, error) {
	f, err := os.Open(path) //#nosec G304 -- path from trusted config
	if err != nil {
		return nil, fmt.Errorf("open requirements.txt: %w", err)
	}
	defer func() { _ = f.Close() }()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Only handle exact pins: requests==2.28.0
		if !strings.Contains(line, "==") {
			continue
		}

		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		ver := strings.TrimSpace(parts[1])
		if name == "" || ver == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   ver,
			Ecosystem: "PyPI",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan requirements.txt: %w", err)
	}
	return deps, nil
}

// parseCargoToml extracts crates.io dependencies from Cargo.toml.
// It requires github.com/pelletier/go-toml/v2 which is already a dep.
func parseCargoToml(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	// Use a minimal TOML parser via a simple line-scanner rather than pulling
	// in a TOML library for this narrow use case. We only need [dependencies]
	// table entries in the format:  name = "version"  or  name = { version = "x" }
	deps := parseCargoLines(string(data))
	return deps, nil
}

func parseCargoLines(content string) []Dependency {
	var deps []Dependency
	inDepsSection := false

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)

		if line == "[dependencies]" || line == "[dev-dependencies]" {
			inDepsSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDepsSection = false
			continue
		}

		if !inDepsSection || line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// name = "1.2.3"
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eqIdx])
		rest := strings.TrimSpace(line[eqIdx+1:])

		// Extract version string from either  "1.2.3"  or  { version = "1.2.3", ... }
		ver := extractCargoVersion(rest)
		if name == "" || ver == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   ver,
			Ecosystem: "crates.io",
		})
	}
	return deps
}

func extractCargoVersion(s string) string {
	s = strings.TrimSpace(s)
	// Plain string: "1.2.3"
	if strings.HasPrefix(s, `"`) {
		s = strings.Trim(s, `"`)
		return strings.TrimLeft(s, "^~>=<")
	}
	// Inline table: { version = "1.2.3", features = [...] }
	if strings.HasPrefix(s, "{") {
		if idx := strings.Index(s, `version = "`); idx >= 0 {
			rest := s[idx+len(`version = "`):]
			if end := strings.Index(rest, `"`); end >= 0 {
				return strings.TrimLeft(rest[:end], "^~>=<")
			}
		}
	}
	return ""
}
