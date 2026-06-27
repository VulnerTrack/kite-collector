package windrivers

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultRoots is the canonical pair of directories the I/O
// manager (and PnP) load kernel drivers from. The collector walks
// each recursively.
//
// The parser + walker are OS-agnostic; on non-Windows hosts the
// roots don't exist and Collect returns an empty slice.
type rootSeed struct {
	path string
	kind SourceRoot
}

// DefaultRoots returns the canonical (path, kind) pairs.
func DefaultRoots() []struct {
	Path string
	Kind SourceRoot
} {
	return []struct {
		Path string
		Kind SourceRoot
	}{
		{`C:\Windows\System32\drivers`, SourceSystem32Drivers},
		{`C:\Windows\System32\DriverStore\FileRepository`, SourceDriverStore},
	}
}

// fileCollector walks the drivers tree from a configurable seed
// list. Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	roots    []rootSeed
}

// NewCollector returns a Collector wired to the canonical drivers
// roots. On hosts without Windows, the roots don't exist and
// Collect returns an empty slice without error.
func NewCollector() Collector {
	defaults := DefaultRoots()
	seeds := make([]rootSeed, 0, len(defaults))
	for _, d := range defaults {
		seeds = append(seeds, rootSeed{path: d.Path, kind: d.Kind})
	}
	return &fileCollector{
		roots:    seeds,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "windrivers" }

func (c *fileCollector) Collect(_ context.Context) ([]Driver, error) {
	out := make([]Driver, 0, 512)
	for _, seed := range c.roots {
		if err := c.walk(seed.path, seed.path, seed.kind, &out); err != nil {
			return nil, err
		}
		if len(out) >= MaxDrivers {
			break
		}
	}
	SortDrivers(out)
	return out, nil
}

// walk recursively enumerates `path` and emits one Driver per
// file. `rootPath` stays fixed so we can compute parent_subdir
// relative to the discovery root.
func (c *fileCollector) walk(path, rootPath string, kind SourceRoot, out *[]Driver) error {
	entries, err := c.readDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(path, name)
		if e.IsDir() {
			if err := c.walk(full, rootPath, kind, out); err != nil {
				return err
			}
			if len(*out) >= MaxDrivers {
				return nil
			}
			continue
		}
		d := Driver{
			FilePath:      full,
			FileName:      name,
			FileExtension: strings.ToLower(filepath.Ext(name)),
			SourceRoot:    kind,
			ParentSubdir:  immediateSubdir(rootPath, full),
		}
		if fi, err := c.statFile(full); err == nil {
			d.FileSizeBytes = fi.Size()
			d.FileMtime = fi.ModTime().Unix()
		}
		// Hash only when the file size is sane; oversized files
		// blow the memory budget and almost certainly aren't
		// kernel drivers.
		if d.FileSizeBytes > 0 && d.FileSizeBytes <= MaxFileBytesForHash {
			if body, err := c.readFile(full); err == nil {
				d.FileHash = HashContents(body)
			}
		}
		AnnotateSecurity(&d)
		*out = append(*out, d)
		if len(*out) >= MaxDrivers {
			return nil
		}
	}
	return nil
}

// immediateSubdir returns the first directory segment between
// `rootPath` and `full`. For files at the top level the result is
// the empty string. The result is OS-portable (slashes
// normalised, then split on `/`).
func immediateSubdir(rootPath, full string) string {
	rel, err := filepath.Rel(rootPath, full)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	// Strip the file name; we want the *directory* part only.
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir := rel[:i]
		if j := strings.Index(dir, "/"); j >= 0 {
			return dir[:j]
		}
		return dir
	}
	return ""
}
