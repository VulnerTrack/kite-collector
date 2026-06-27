package winmsix

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultMachineWideRoot is the canonical machine-wide MSIX
// install directory. Each immediate subdirectory is a package
// full-name; the AppxManifest.xml lives directly inside.
const DefaultMachineWideRoot = `C:\Program Files\WindowsApps`

// fileCollector walks WindowsApps from a configurable root.
// Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile        func(string) ([]byte, error)
	readDir         func(string) ([]os.DirEntry, error)
	statFile        func(string) (os.FileInfo, error)
	machineWideRoot string
}

// NewCollector returns a Collector wired to the canonical
// WindowsApps root. Missing root → empty slice (Windows host
// without the WindowsApps dir, or non-Windows OS).
func NewCollector() Collector {
	return &fileCollector{
		machineWideRoot: DefaultMachineWideRoot,
		readFile:        os.ReadFile,
		readDir:         os.ReadDir,
		statFile:        os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winmsix" }

func (c *fileCollector) Collect(_ context.Context) ([]Package, error) {
	out := make([]Package, 0, 64)
	c.harvestRoot(c.machineWideRoot, ScopeMachineWide, &out)
	if len(out) > MaxPackages {
		out = out[:MaxPackages]
	}
	SortPackages(out)
	return out, nil
}

// harvestRoot lists the immediate subdirectories of `root`
// (each = one package full name) and parses the contained
// AppxManifest.xml.
func (c *fileCollector) harvestRoot(root string, scope InstallScope, out *[]Package) {
	entries, err := c.readDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		pkgDir := filepath.Join(root, name)
		manifestPath := filepath.Join(pkgDir, "AppxManifest.xml")
		body, err := c.readFile(manifestPath)
		if err != nil {
			continue
		}
		pkg, err := ParseAppxManifest(body)
		if err != nil {
			continue
		}
		pkg.FilePath = manifestPath
		pkg.FileHash = HashContents(body)
		pkg.PackageDir = pkgDir
		pkg.PackageFullName = name
		pkg.InstallScope = scope
		AnnotateSecurity(&pkg)
		*out = append(*out, pkg)
		if len(*out) >= MaxPackages {
			return
		}
	}
}
