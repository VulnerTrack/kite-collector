package windsc

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultConfigurationRoot is the canonical Windows DSC
// configuration directory.
const DefaultConfigurationRoot = `C:\Windows\System32\Configuration`

// fileCollector walks .mof files from a configurable root.
// Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

// NewCollector returns a Collector wired to the canonical
// Configuration directory. Missing root → empty slice (non-DSC
// host or non-Windows OS).
func NewCollector() Collector {
	return &fileCollector{
		root:     DefaultConfigurationRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "windsc" }

func (c *fileCollector) Collect(_ context.Context) ([]Resource, error) {
	entries, err := c.readDir(c.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	out := make([]Resource, 0, 32)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.EqualFold(filepath.Ext(name), ".mof") {
			continue
		}
		full := filepath.Join(c.root, name)
		body, err := c.readFile(full)
		if err != nil {
			continue
		}
		kind := NormalizeMOFKind(name)
		out = append(out, ParseMOF(body, full, kind)...)
		if len(out) >= MaxResources {
			break
		}
	}

	if len(out) > MaxResources {
		out = out[:MaxResources]
	}
	SortResources(out)
	return out, nil
}
