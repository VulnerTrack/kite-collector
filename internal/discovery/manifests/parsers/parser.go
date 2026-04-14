package parsers

import "context"

// ManifestParser reads a dependency manifest file and returns discovered
// software. Parsers MUST NOT shell out to external binaries — they parse
// the file directly from disk.
type ManifestParser interface {
	// Patterns returns the filename globs this parser handles.
	Patterns() []string

	// Parse reads the file at path and returns extracted dependencies.
	// Fatal errors (corrupt file, unreadable) return error.
	// Per-dependency parse failures are recorded in ParseResult.Errors.
	Parse(ctx context.Context, path string, content []byte) (*ParseResult, error)

	// Ecosystem returns the language/runtime ecosystem identifier.
	// Used for CPE target_sw field.
	Ecosystem() string
}

// ParseResult holds the output of a single manifest parse.
type ParseResult struct {
	// ProjectName is the name from the manifest (e.g., "name" in package.json).
	ProjectName string

	// ProjectVersion is the version from the manifest.
	ProjectVersion string

	// ManifestPath is the absolute path to the parsed file.
	ManifestPath string

	// Dependencies are the extracted packages.
	Dependencies []Dependency

	// Errors holds non-fatal per-dependency parse errors.
	Errors []string

	// LockfileUsed indicates this was parsed from a lockfile (exact versions).
	LockfileUsed bool
}

// Dependency represents a single declared or resolved dependency.
type Dependency struct {
	Name    string // package name (e.g., "express", "laravel/framework")
	Version string // declared or resolved version
	Vendor  string // extracted vendor (e.g., "laravel" from "laravel/framework")
	Scope   string // "runtime", "dev", "build", "test", "optional"
	Direct  bool   // true if declared in manifest, false if transitive
}
