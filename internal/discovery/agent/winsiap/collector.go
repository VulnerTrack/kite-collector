package winsiap

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fileCollector walks SIAP install roots. Test seam swaps
// readDir / statFile / getenv / now.
type fileCollector struct {
	now          func() time.Time
	getenv       func(string) string
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		getenv:       os.Getenv,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          time.Now,
	}
}

func (c *fileCollector) Name() string { return "winsiap" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SIAP_HOME")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, root := range roots {
		c.walkRoot(root, &out)
		if len(out) >= MaxRows {
			break
		}
	}

	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortRows(out)
	return out, nil
}

// walkRoot probes one SIAP install root: finds the
// `Aplicaciones` subdir, then each application dir, then each
// per-CUIT subdir.
func (c *fileCollector) walkRoot(root string, out *[]Row) {
	rootEntries, err := c.readDir(root)
	if err != nil {
		return
	}

	var appsDirPath string
	for _, e := range rootEntries {
		if !e.IsDir() {
			continue
		}
		for _, candidate := range AplicacionesDirNames() {
			if strings.EqualFold(e.Name(), candidate) {
				appsDirPath = filepath.Join(root, e.Name())
				break
			}
		}
		if appsDirPath != "" {
			break
		}
	}
	if appsDirPath == "" {
		return
	}

	apps, err := c.readDir(appsDirPath)
	if err != nil {
		return
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name() < apps[j].Name() })

	for _, app := range apps {
		if !app.IsDir() {
			continue
		}
		appPath := filepath.Join(appsDirPath, app.Name())
		c.walkApp(root, appPath, app.Name(), out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

// walkApp enumerates per-CUIT subdirs under one application.
func (c *fileCollector) walkApp(root, appPath, appName string, out *[]Row) {
	entries, err := c.readDir(appPath)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	cuitSubdirs := make([]os.DirEntry, 0)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if prefix, _ := CuitFingerprintFromSubdir(e.Name()); prefix != "" {
			cuitSubdirs = append(cuitSubdirs, e)
		}
	}

	multiTenant := len(cuitSubdirs) > 1

	if len(cuitSubdirs) == 0 {
		// App is installed but no per-CUIT data dir yet.
		c.emit(root, appPath, appName, "", false, out)
		return
	}
	for _, e := range cuitSubdirs {
		c.emit(root, appPath, appName, e.Name(), multiTenant, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

// emit builds one Row from a (root, app, cuit-subdir) tuple.
func (c *fileCollector) emit(root, appPath, appName, cuitSubdir string, multiTenant bool, out *[]Row) {
	row := Row{
		InstallRoot:            root,
		ApplicationDir:         appPath,
		CuitDir:                cuitSubdir,
		ApplicationName:        appName,
		ApplicationCategory:    CategoryFromAppName(appName),
		IsLegacySIAP:           true,
		HasMultipleCuitSubdirs: multiTenant,
	}
	if cuitSubdir != "" {
		row.CuitEntityPrefix, row.CuitSuffix4 = CuitFingerprintFromSubdir(cuitSubdir)
	}

	// Stat the (cuit-subdir or app-dir) for mode/owner.
	target := appPath
	if cuitSubdir != "" {
		target = filepath.Join(appPath, cuitSubdir)
	}
	if fi, err := c.statFile(target); err == nil {
		row.DirMode = int(fi.Mode().Perm())
		row.DirOwnerUID = ownerUID(fi)
	}

	// Inspect data files inside the cuit subdir (or app dir).
	c.countDataFiles(target, &row)

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

// countDataFiles totals data files inside `dir` and records
// the most-recent mtime.
func (c *fileCollector) countDataFiles(dir string, row *Row) {
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if !IsDataFileExt(ext) {
			continue
		}
		row.DataFilesCount++
		lower := strings.ToLower(ext)
		switch lower {
		case ".dat":
			row.DatFilesCount++
		case ".dbf":
			row.DbfFilesCount++
		}
		fi, err := c.statFile(filepath.Join(dir, e.Name()))
		if err == nil {
			mt := fi.ModTime()
			if mt.After(newest) {
				newest = mt
			}
		}
	}
	if !newest.IsZero() {
		row.LastModified = newest.UTC().Format(time.RFC3339)
		if c.now().Sub(newest) <= RecentlyModifiedWindow {
			row.IsRecentlyModified = true
		}
	}
}
