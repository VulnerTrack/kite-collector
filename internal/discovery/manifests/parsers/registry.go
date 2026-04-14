package parsers

import "path/filepath"

// Registry maps filename patterns to parsers.
type Registry struct {
	exact map[string]ManifestParser
	globs []globEntry
}

type globEntry struct {
	parser  ManifestParser
	pattern string
}

// NewRegistry returns a registry pre-loaded with all known parsers.
func NewRegistry() *Registry {
	r := &Registry{exact: make(map[string]ManifestParser)}

	all := []ManifestParser{
		&NodeParser{},
		&NodeLockParser{},
		&ComposerParser{},
		&ComposerLockParser{},
		&RequirementsParser{},
		&PipfileLockParser{},
		&PoetryLockParser{},
		&UvLockParser{},
		&GoModParser{},
		&CargoTomlParser{},
		&CargoLockParser{},
		&GemfileParser{},
		&GemfileLockParser{},
	}

	for _, p := range all {
		r.register(p)
	}
	return r
}

func (r *Registry) register(p ManifestParser) {
	for _, pat := range p.Patterns() {
		if isGlob(pat) {
			r.globs = append(r.globs, globEntry{pattern: pat, parser: p})
		} else {
			r.exact[pat] = p
		}
	}
}

// Match returns the parser for the given base filename, or nil.
func (r *Registry) Match(filename string) ManifestParser {
	if p, ok := r.exact[filename]; ok {
		return p
	}
	for _, g := range r.globs {
		if matched, _ := filepath.Match(g.pattern, filename); matched {
			return g.parser
		}
	}
	return nil
}

// Filenames returns the set of exact filename matches (not globs).
func (r *Registry) Filenames() map[string]struct{} {
	out := make(map[string]struct{}, len(r.exact))
	for k := range r.exact {
		out[k] = struct{}{}
	}
	return out
}

// GlobPatterns returns all glob patterns registered.
func (r *Registry) GlobPatterns() []string {
	out := make([]string, len(r.globs))
	for i, g := range r.globs {
		out[i] = g.pattern
	}
	return out
}

// LockfileOverrides maps a lockfile filename to the manifest it supersedes.
// Used for lockfile preference: if both exist in the same directory, the
// lockfile is preferred and the manifest is skipped.
var LockfileOverrides = map[string]string{
	"package-lock.json": "package.json",
	"yarn.lock":         "package.json",
	"pnpm-lock.yaml":    "package.json",
	"composer.lock":      "composer.json",
	"Cargo.lock":         "Cargo.toml",
	"Gemfile.lock":       "Gemfile",
}

func isGlob(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}
