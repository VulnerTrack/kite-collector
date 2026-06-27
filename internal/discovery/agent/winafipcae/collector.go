package winafipcae

import (
	"context"
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

// MaxWalkDepth bounds per-user tree depth.
const MaxWalkDepth = 6

// fileCollector walks per-user trees looking for AFIP CAE
// receipt XMLs. Test seam swaps readFile / readDir / statFile
// / getenv.
type fileCollector struct {
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winafipcae" }

func (c *fileCollector) Collect(_ context.Context) ([]Receipt, error) {
	out := make([]Receipt, 0, 32)

	for _, k := range []string{"PYAFIPWS_HOME", "AFIPSDK_CAE_DIR", "AFIP_FACTURAS_DIR"} {
		if p := strings.TrimSpace(c.getenv(k)); p != "" {
			c.walk(p, "", &out, 0)
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
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
			c.walk(filepath.Join(base, name), name, &out, 0)
			if len(out) >= MaxReceipts {
				break
			}
		}
		if len(out) >= MaxReceipts {
			break
		}
	}

	if len(out) > MaxReceipts {
		out = out[:MaxReceipts]
	}
	SortReceipts(out)
	return out, nil
}

func (c *fileCollector) walk(dir, user string, out *[]Receipt, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxReceipts {
				return
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(e.Name()), ".xml") {
			continue
		}
		if !IsAfipPath(full) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxReceipts {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, out *[]Receipt) {
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	if fi.Size() > MaxFileBytes {
		return
	}
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	r, ok := ParseCAEReceipt(body)
	if !ok {
		return
	}
	r.FilePath = path
	r.FileHash = HashContents(body)
	r.FileSize = fi.Size()
	r.FileMode = int(fi.Mode().Perm())
	r.FileOwnerUID = ownerUID(fi)
	r.UserProfile = user
	AnnotateSecurity(&r)
	*out = append(*out, r)
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
