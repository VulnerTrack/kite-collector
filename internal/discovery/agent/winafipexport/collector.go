package winafipexport

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks export-invoice install roots + per-user
// dirs.
type fileCollector struct {
	getenv       func(string) string
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []string
	usersBases   []string
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		usersBases:   DefaultUsersBases(),
		getenv:       os.Getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winafipexport" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AFIP_EXPORT_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("WSMTXCA_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, r := range roots {
		c.walk(r, "", &out, 0)
		if len(out) >= MaxRows {
			break
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			for _, rel := range UserExportDirs() {
				c.walk(filepath.Join(append([]string{base, name}, rel...)...),
					name, &out, 0)
				if len(out) >= MaxRows {
					break
				}
			}
			if len(out) >= MaxRows {
				break
			}
		}
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

func (c *fileCollector) walk(dir, user string, out *[]Row, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxRows {
				return
			}
			continue
		}
		if !isCandidateExt(e.Name()) {
			continue
		}
		if !IsCandidateName(e.Name()) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

var periodRE = regexp.MustCompile(`(20\d{2})[-_]?(0[1-9]|1[0-2])`)

func periodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

func cuitFingerprintFromName(name string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(name)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

func (c *fileCollector) consider(path, user string, out *[]Row) {
	// Dedupe.
	for _, existing := range *out {
		if existing.FilePath == path {
			return
		}
	}
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		WSKind:       WSKindFromName(filepath.Base(path)),
		PeriodYYYYMM: periodFromName(filepath.Base(path)),
	}
	if prefix, suffix := cuitFingerprintFromName(filepath.Base(path)); prefix != "" {
		row.CuitEmisorPrefix = prefix
		row.CuitEmisorSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".xml" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseExportInvoice(body); ok {
				if row.CuitEmisorPrefix == "" && fields.CuitEmisorRaw != "" {
					row.CuitEmisorPrefix, row.CuitEmisorSuffix4 = cuitFingerprintFromName(fields.CuitEmisorRaw)
				}
				if row.CaeCode == "" {
					row.CaeCode = fields.CAE
				}
				if row.CbteTipo == 0 {
					row.CbteTipo = fields.CbteTipo
				}
				if row.CbteFch == "" {
					row.CbteFch = fields.CbteFch
				}
				if row.PtoVta == 0 {
					row.PtoVta = fields.PtoVta
				}
				if row.CbteNro == 0 {
					row.CbteNro = fields.CbteNro
				}
				if row.Incoterm == "" {
					row.Incoterm = IncotermFromText(fields.IncotermRaw)
				}
				if row.DestinoCountry == "" {
					if normalised := NormaliseDestino(fields.DestinoCountry); normalised != "" {
						row.DestinoCountry = normalised
					} else {
						row.DestinoCountry = CountryCodeFromText(fields.DestinoCountry)
					}
				}
				if row.Moneda == "" {
					row.Moneda = strings.ToUpper(strings.TrimSpace(fields.Moneda))
				}
				if row.CotizacionARS == 0 {
					row.CotizacionARS = fields.CotizacionARS
				}
				if row.ImpTotalCents == 0 {
					row.ImpTotalCents = fields.ImpTotalCents
				}
				if row.ImpTotalUSDCents == 0 {
					row.ImpTotalUSDCents = fields.ImpTotalUSDCents
				}
				if row.Idioma == "" {
					row.Idioma = strings.ToLower(strings.TrimSpace(fields.Idioma))
				}
			}
		}
	}
	if row.Incoterm == "" {
		row.Incoterm = IncoUnknown
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".txt":
		return true
	}
	return false
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
