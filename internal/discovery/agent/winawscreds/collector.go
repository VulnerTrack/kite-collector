package winawscreds

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

// AWSDirRelComponents is the per-user relative path to the .aws
// directory; kept as a slice so filepath.Join produces native
// separators.
var AWSDirRelComponents = []string{".aws"}

// fileCollector walks AWS credentials/config files from per-user
// trees plus the AWS_*_FILE env vars. Test seam swaps readFile /
// readDir / statFile / getenv.
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

func (c *fileCollector) Name() string { return "winawscreds" }

func (c *fileCollector) Collect(_ context.Context) ([]Profile, error) {
	out := make([]Profile, 0, 16)

	// Env-var overrides.
	if p := c.getenv("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
		c.harvestFile(p, "", FileCredentials, &out)
	}
	if p := c.getenv("AWS_CONFIG_FILE"); p != "" {
		c.harvestFile(p, "", FileConfig, &out)
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
			awsDir := filepath.Join(append([]string{base, name}, AWSDirRelComponents...)...)
			c.harvestFile(filepath.Join(awsDir, "credentials"), name, FileCredentials, &out)
			c.harvestFile(filepath.Join(awsDir, "config"), name, FileConfig, &out)
			if len(out) >= MaxProfiles {
				break
			}
		}
		if len(out) >= MaxProfiles {
			break
		}
	}

	if len(out) > MaxProfiles {
		out = out[:MaxProfiles]
	}
	SortProfiles(out)
	return out, nil
}

// harvestFile reads + parses a single AWS file and appends each
// discovered profile (stamped with file metadata) to `out`.
// Missing files / parse errors silently skip.
func (c *fileCollector) harvestFile(path, user string, kind FileKind, out *[]Profile) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseFile(body, kind)
	if len(parsed) == 0 {
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
		if len(*out) >= MaxProfiles {
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
