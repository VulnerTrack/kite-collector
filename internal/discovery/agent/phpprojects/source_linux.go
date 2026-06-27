//go:build linux

package phpprojects

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultSearchRoots is the curated set of canonical install
// roots scanned by the production source. Override with the
// PHP_PROJECTS_DIR env var (colon-separated list).
var DefaultSearchRoots = []string{
	"/var/www",
	"/var/www/html",
	"/srv/www",
	"/srv/http",
	"/usr/share/phpmyadmin",
	"/usr/share/nextcloud",
	"/usr/share/owncloud",
	"/usr/share/wordpress",
	"/usr/share/mediawiki",
	"/opt",
}

// PerUserSubdirs is the per-$HOME paths visited under each
// detected user under /home (or /Users for symmetry on macOS,
// but this file is Linux-only).
var PerUserSubdirs = []string{
	"public_html",
	"www",
	"sites",
	"projects",
	"src",
	"work",
	"Documents/Projects",
	"Documents/Sites",
}

// WebRootPrefixes flag projects sitting under a typical
// web-serving directory — used by Annotate's IsUnderWebRoot
// risk signal. Per-user public_html / www paths are caught by
// the suffix check in pathIsUnderWebRoot rather than by listing
// `/home/` here (which would over-match every developer's home).
var WebRootPrefixes = []string{
	"/var/www/",
	"/srv/www/",
	"/srv/http/",
	"/usr/share/nginx/",
	"/usr/share/apache2/",
}

// MaxScanDepth bounds how deep we descend from each search root
// looking for project markers. Each subdir is treated as a
// candidate project root before we descend further.
const MaxScanDepth = 4

type linuxSource struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	stat     func(string) (os.FileInfo, error)
	homeRoot string
	roots    []string
	maxDepth int
}

func newSource() Source {
	return &linuxSource{
		getenv:   os.Getenv,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		stat:     os.Stat,
		roots:    DefaultSearchRoots,
		homeRoot: "/home",
		maxDepth: MaxScanDepth,
	}
}

// NewLinuxSource lets callers inject roots + home base.
func NewLinuxSource(roots []string, homeRoot string) Source {
	return &linuxSource{
		getenv:   os.Getenv,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		stat:     os.Stat,
		roots:    roots,
		homeRoot: homeRoot,
		maxDepth: MaxScanDepth,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Project, error) {
	seen := map[string]bool{}
	var out []Project

	roots := append([]string{}, s.roots...)
	if extra := strings.TrimSpace(s.getenv("PHP_PROJECTS_DIR")); extra != "" {
		for _, p := range strings.Split(extra, ":") {
			if p = strings.TrimSpace(p); p != "" {
				roots = append([]string{p}, roots...)
			}
		}
	}

	for _, r := range roots {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		s.walk(r, "", &out, seen, 0)
		if len(out) >= MaxRows {
			break
		}
	}

	// Per-user scan.
	if entries, err := s.readDir(s.homeRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			user := e.Name()
			home := filepath.Join(s.homeRoot, user)
			for _, sub := range PerUserSubdirs {
				if err := ctx.Err(); err != nil {
					return out, fmt.Errorf("ctx cancelled: %w", err)
				}
				s.walk(filepath.Join(home, sub), user, &out, seen, 0)
				if len(out) >= MaxRows {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

// walk descends into `dir`, classifying each directory as a
// candidate project root. Matched projects are appended and the
// walk does NOT descend further into them (one project per
// subtree).
func (s *linuxSource) walk(dir, user string, out *[]Project, seen map[string]bool, depth int) {
	if depth > s.maxDepth {
		return
	}
	if seen[dir] {
		return
	}
	seen[dir] = true

	fi, err := s.stat(dir)
	if err != nil || !fi.IsDir() {
		return
	}

	// Try to classify this directory as a project root first.
	if p, ok := s.classify(dir, user); ok {
		*out = append(*out, p)
		// Don't descend into the matched project.
		return
	}

	// Otherwise descend into immediate children.
	entries, err := s.readDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if isSkipDir(name) {
			continue
		}
		s.walk(filepath.Join(dir, name), user, out, seen, depth+1)
		if len(*out) >= MaxRows {
			return
		}
	}
}

// classify wraps ClassifyDir + populates the per-row environment
// flags (.env presence, vendor/ presence, git repo, etc.).
func (s *linuxSource) classify(dir, user string) (Project, bool) {
	exists := func(p string) bool {
		_, err := s.stat(p)
		return err == nil
	}
	p, ok := ClassifyDir(dir, exists, s.readFile)
	if !ok {
		return Project{}, false
	}
	p.UserProfile = user
	p.ComposerJSONPresent = exists(filepath.Join(dir, "composer.json"))
	p.ComposerLockPresent = exists(filepath.Join(dir, "composer.lock"))
	p.HasVendorDir = exists(filepath.Join(dir, "vendor"))
	p.HasNodeModulesDir = exists(filepath.Join(dir, "node_modules"))
	p.IsGitRepo = exists(filepath.Join(dir, ".git"))
	p.IsUnderWebRoot = pathIsUnderWebRoot(dir)
	p.HasDotenv = exists(filepath.Join(dir, ".env"))
	if p.HasDotenv {
		if data, err := s.readFile(filepath.Join(dir, ".env")); err == nil {
			p.HasDotenvSecret = HasSecretShapedKey(data)
		}
	}
	if exists(filepath.Join(dir, "install")) ||
		exists(filepath.Join(dir, "setup")) ||
		exists(filepath.Join(dir, "installation")) {
		p.HasInstallWizard = true
	}
	// Permission probes.
	if fi, err := s.stat(dir); err == nil {
		mode := fi.Mode().Perm()
		if mode&0o002 != 0 {
			p.IsWorldWritableRoot = true
		}
	}
	if p.HasDotenv {
		if fi, err := s.stat(filepath.Join(dir, ".env")); err == nil {
			mode := fi.Mode().Perm()
			if mode&0o004 != 0 {
				p.IsWorldReadableConfig = true
			}
		}
	}
	// Best-effort project size (top-level only — full walk would
	// blow the I/O budget on large projects).
	if entries, err := s.readDir(dir); err == nil {
		p.FileCount = len(entries)
	}
	return p, true
}

// pathIsUnderWebRoot reports whether `dir` sits under a typical
// web-serving root.
func pathIsUnderWebRoot(dir string) bool {
	for _, prefix := range WebRootPrefixes {
		if strings.HasPrefix(dir, prefix) {
			return true
		}
	}
	// Per-user public_html / www suffix probe.
	if strings.Contains(dir, "/public_html/") ||
		strings.HasSuffix(dir, "/public_html") ||
		strings.Contains(dir, "/www/") {
		return true
	}
	return false
}

// isSkipDir lists directory names we never descend into during
// the walk — these are noise or would cause infinite churn.
func isSkipDir(name string) bool {
	switch name {
	case ".git", ".svn", ".hg", "node_modules", "vendor",
		".cache", ".tmp", "tmp", "cache", "__pycache__",
		"venv", ".venv", "env", ".env.d",
		"target", "build", "dist", "out", "release",
		".idea", ".vscode":
		return true
	}
	if strings.HasPrefix(name, ".") {
		// Skip dotfiles / dotdirs at scan time. The .env file
		// itself is read by classify(), not walked through.
		return true
	}
	return false
}

// secretShapedRE matches keys in a .env file that look like
// they hold a secret value. Match is on the key only — we never
// extract or persist the secret itself.
var secretShapedRE = regexp.MustCompile(`(?im)^[A-Z][A-Z0-9_]*(?:_PASSWORD|_SECRET|_KEY|_TOKEN|_API_KEY|_ACCESS_KEY|_PRIVATE_KEY|_AUTH|_CREDENTIALS|APP_KEY|DB_PASS|DB_PASSWORD)\s*=\s*\S+`)

// HasSecretShapedKey reports whether the .env contents include
// at least one secret-shaped key assignment with a non-empty
// value. Only the presence is reported; never the value.
func HasSecretShapedKey(envBody []byte) bool {
	return secretShapedRE.Match(envBody)
}
