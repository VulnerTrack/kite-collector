package winkubeconfig

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// DefaultUsersBases is the curated set of per-OS user-profile
// bases the collector walks to discover per-user .kube/config
// files.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// KubeconfigRelComponents is the per-user relative path. Kept as
// a slice so filepath.Join produces native separators.
var KubeconfigRelComponents = []string{".kube", "config"}

// fileCollector walks kubeconfig files from per-user trees plus
// any path listed in the `KUBECONFIG` env var. Test seam swaps
// readFile / readDir / statFile / getenv.
type fileCollector struct {
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
	rootFiles  []string
}

// NewCollector returns a Collector wired to the canonical per-OS
// paths. Missing paths are silently skipped.
func NewCollector() Collector {
	roots := []string{}
	if runtime.GOOS != "windows" {
		roots = append(roots, "/root/.kube/config")
	}
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		rootFiles:  roots,
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winkubeconfig" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 16)

	// KUBECONFIG env var (colon-separated list on POSIX,
	// semicolon-separated on Windows).
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	for _, p := range splitNonEmpty(c.getenv("KUBECONFIG"), sep) {
		c.harvestFile(p, "", &out)
		if len(out) >= MaxEntries {
			break
		}
	}

	// Root file(s) — /root/.kube/config on Linux/macOS.
	for _, p := range c.rootFiles {
		c.harvestFile(p, "root", &out)
		if len(out) >= MaxEntries {
			break
		}
	}

	// Per-user discovery via each user-base directory.
	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(append([]string{base, name}, KubeconfigRelComponents...)...)
			c.harvestFile(path, name, &out)
			if len(out) >= MaxEntries {
				break
			}
		}
		if len(out) >= MaxEntries {
			break
		}
	}

	if len(out) > MaxEntries {
		out = out[:MaxEntries]
	}
	SortEntries(out)
	return out, nil
}

// harvestFile reads + parses a single kubeconfig and appends its
// entries (stamped with file metadata) to `out`. Missing files
// or parse errors are silently skipped.
func (c *fileCollector) harvestFile(path, user string, out *[]Entry) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed, err := ParseKubeconfig(body)
	if err != nil {
		return
	}
	hash := HashContents(body)
	mode := 0
	uid := 0
	if fi, err := c.statFile(path); err == nil {
		mode = int(fi.Mode().Perm())
		uid = ownerUID(fi)
	}
	for _, p := range parsed {
		p.FilePath = path
		p.FileHash = hash
		p.FileMode = mode
		p.FileOwnerUID = uid
		p.UserProfile = user
		AnnotateSecurity(&p)
		*out = append(*out, p)
		if len(*out) >= MaxEntries {
			return
		}
	}
}

// splitNonEmpty splits `s` on `sep` and drops empty fragments.
func splitNonEmpty(s, sep string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
