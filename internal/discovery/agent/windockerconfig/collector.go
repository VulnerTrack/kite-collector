package windockerconfig

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUsersBases is the curated set of per-OS user-profile
// bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// DockerConfigRelComponents is the per-user relative path.
var DockerConfigRelComponents = []string{".docker", "config.json"}

// fileCollector walks `.docker/config.json` files from per-user
// trees + `DOCKER_CONFIG` env override. Test seam swaps readFile
// / readDir / statFile / getenv.
type fileCollector struct {
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
}

// NewCollector returns a Collector wired to the canonical per-OS
// paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
}

func (c *fileCollector) Name() string { return "windockerconfig" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 8)

	// DOCKER_CONFIG env-var override.
	if dir := strings.TrimSpace(c.getenv("DOCKER_CONFIG")); dir != "" {
		c.harvestFile(filepath.Join(dir, "config.json"), "", &out)
	}

	// Per-user discovery.
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
			path := filepath.Join(append([]string{base, name}, DockerConfigRelComponents...)...)
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

// harvestFile reads + parses a single Docker config and appends
// each discovered entry (stamped with file metadata) to `out`.
// Missing files / parse errors silently skip.
func (c *fileCollector) harvestFile(path, user string, out *[]Entry) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed, err := ParseConfig(body)
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

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
