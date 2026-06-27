package wintango

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fileCollector walks ERP install roots. Test seam swaps
// readFile / readDir / statFile / getenv / now.
type fileCollector struct {
	now          func() time.Time
	getenv       func(string) string
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []InstallRoot
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		getenv:       os.Getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          time.Now,
	}
}

func (c *fileCollector) Name() string { return "wintango" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]InstallRoot{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("TANGO_HOME")); p != "" {
		roots = append([]InstallRoot{{Path: p, Vendor: VendorTango}}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("BEJERMAN_HOME")); p != "" {
		roots = append([]InstallRoot{{Path: p, Vendor: VendorBejerman}}, roots...)
	}

	for _, r := range roots {
		c.walkRoot(r, &out)
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

func (c *fileCollector) walkRoot(root InstallRoot, out *[]Row) {
	entries, err := c.readDir(root.Path)
	if err != nil {
		return
	}
	var empresasDirPath string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, candidate := range EmpresasDirNames() {
			if strings.EqualFold(e.Name(), candidate) {
				empresasDirPath = filepath.Join(root.Path, e.Name())
				break
			}
		}
		if empresasDirPath != "" {
			break
		}
	}
	if empresasDirPath == "" {
		return
	}

	empresas, err := c.readDir(empresasDirPath)
	if err != nil {
		return
	}
	sort.Slice(empresas, func(i, j int) bool { return empresas[i].Name() < empresas[j].Name() })

	empresaDirs := make([]os.DirEntry, 0, len(empresas))
	for _, e := range empresas {
		if e.IsDir() {
			empresaDirs = append(empresaDirs, e)
		}
	}
	multiTenant := len(empresaDirs) > 1

	for _, e := range empresaDirs {
		empPath := filepath.Join(empresasDirPath, e.Name())
		c.emit(root, empPath, e.Name(), multiTenant, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func (c *fileCollector) emit(root InstallRoot, empPath, empName string, multiTenant bool, out *[]Row) {
	row := Row{
		InstallRoot:         root.Path,
		EmpresaDir:          empPath,
		EmpresaName:         empName,
		Vendor:              root.Vendor,
		HasMultipleEmpresas: multiTenant,
	}

	if fi, err := c.statFile(empPath); err == nil {
		row.DirMode = int(fi.Mode().Perm())
		row.DirOwnerUID = ownerUID(fi)
	}

	c.scanEmpresa(empPath, &row)

	// Look for Empresas.cnf / Empresas.ini / Empresa.ini at
	// the empresa root for CUIT + denominacion.
	for _, name := range []string{"Empresa.cnf", "Empresa.ini", "Empresas.cnf", "Empresas.ini", "tango.ini", "Empresas.dat"} {
		body, err := c.readFile(filepath.Join(empPath, name))
		if err != nil {
			continue
		}
		md := ParseEmpresaConfig(body)
		if md.CuitRaw != "" && row.CuitEntityPrefix == "" {
			row.CuitEntityPrefix, row.CuitSuffix4 = CuitFingerprint(md.CuitRaw)
		}
		if md.Denominacion != "" && row.Denominacion == "" {
			row.Denominacion = TruncateDenominacion(md.Denominacion)
		}
		if row.CuitEntityPrefix != "" && row.Denominacion != "" {
			break
		}
	}

	// Fall back to the directory name itself for the CUIT.
	if row.CuitEntityPrefix == "" {
		row.CuitEntityPrefix, row.CuitSuffix4 = CuitFingerprint(empName)
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

// scanEmpresa walks the empresa dir one level deep, flipping
// module flags + counting data files + computing newest mtime.
func (c *fileCollector) scanEmpresa(dir string, row *Row) {
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() {
			for _, m := range ModuleDirs() {
				if strings.EqualFold(e.Name(), m) {
					SetModuleFlag(row, m)
					row.ModuleCount++
					// Recurse one level to count files inside module.
					moduleNewest := c.countDataFiles(filepath.Join(dir, e.Name()), row)
					if moduleNewest.After(newest) {
						newest = moduleNewest
					}
					break
				}
			}
			continue
		}
		if IsDataFileExt(filepath.Ext(e.Name())) {
			row.DataFilesCount++
			fi, err := c.statFile(filepath.Join(dir, e.Name()))
			if err == nil && fi.ModTime().After(newest) {
				newest = fi.ModTime()
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

// countDataFiles totals data files inside a module dir,
// returning the newest mtime.
func (c *fileCollector) countDataFiles(dir string, row *Row) time.Time {
	var newest time.Time
	entries, err := c.readDir(dir)
	if err != nil {
		return newest
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !IsDataFileExt(filepath.Ext(e.Name())) {
			continue
		}
		row.DataFilesCount++
		fi, err := c.statFile(filepath.Join(dir, e.Name()))
		if err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}
