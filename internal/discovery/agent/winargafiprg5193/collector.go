package winargafiprg5193

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks AFIP install roots + per-user dirs.
type fileCollector struct {
	now          func() time.Time
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
		now:          time.Now,
	}
}

func (c *fileCollector) Name() string { return "winargafiprg5193" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AFIP_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("ARCA_DIR")); p != "" {
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
			for _, rel := range UserAFIPDirs() {
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
		if !IsCandidateExt(e.Name()) {
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

func (c *fileCollector) consider(path, user string, out *[]Row) {
	for _, existing := range *out {
		if existing.FilePath == path {
			return
		}
	}
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	base := filepath.Base(path)
	row := Row{
		FilePath:      path,
		FileSize:      fi.Size(),
		FileMode:      int(fi.Mode().Perm()),
		FileOwnerUID:  ownerUID(fi),
		UserProfile:   user,
		ArtifactKind:  ArtifactKindFromName(base),
		ReporterClass: ReporterUnknown,
		PeriodYYYYMM:  PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" ||
		ext == ".xlsx" || ext == ".xls"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields AFIPFields
	switch row.ArtifactKind {
	case KindConfig, KindSessionToken:
		fields = ParseAFIPCredentials(body)
		if row.ArtifactKind == KindSessionToken {
			f2 := ParseAFIPSessionToken(body)
			if f2.AFIPToken != "" {
				fields.AFIPToken = f2.AFIPToken
			}
		}
	case KindRG5193Daily:
		fields = ParseAFIPRG5193Daily(body)
	case KindRG5527Crypto:
		fields = ParseAFIPRG5527Crypto(body)
	case KindCOTIInversiones:
		fields = ParseAFIPCOTI(body)
	case KindGananciasRetenciones:
		fields = ParseAFIPGananciasRetenciones(body)
	case KindBienesPersonales:
		fields = ParseAFIPBienesPersonales(body)
	case KindF8125Transfer:
		fields = ParseAFIPF8125Transfer(body)
	case KindExteriorizacion:
		fields = ParseAFIPExteriorizacion(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.AFIPToken != "" {
		row.HasAFIPSessionToken = true
		row.AFIPTokenHash = HashSecret(fields.AFIPToken)
	}
	if fields.HasGanancias {
		row.HasGananciasWithholding = true
	}
	if fields.HasBienes {
		row.HasBienesPersonales = true
	}
	if fields.HasPIIBundle {
		row.HasPIINaturalPerson = true
	}
	if fields.ReporterCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ReporterCuitRaw); p != "" {
			row.ReporterCuitPrefix = p
			row.ReporterCuitSuffix4 = s
		}
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if fields.TransactionCount > 0 {
		row.TransactionCount = fields.TransactionCount
	}
	if fields.CryptoTransactions > 0 {
		row.CryptoTransactionCount = fields.CryptoTransactions
	}
	if fields.TotalVolumeARSCents > 0 {
		row.TotalVolumeARSCents = fields.TotalVolumeARSCents
	}
	if fields.TotalVolumeUSDCents > 0 {
		row.TotalVolumeUSDCents = fields.TotalVolumeUSDCents
	}
	if fields.DistinctClientes > 0 {
		row.DistinctClienteCount = fields.DistinctClientes
	}
	if fields.HighValueCount > 0 {
		row.HighValueCount = fields.HighValueCount
	}
	if fields.CrossBorderCount > 0 {
		row.CrossBorderCount = fields.CrossBorderCount
	}
	row.ReporterClass = classifyReporter(row.ArtifactKind, fields)
}

// classifyReporter picks a reporter class from parsed fields.
func classifyReporter(k ArtifactKind, f AFIPFields) ReporterClass {
	if k == KindRG5527Crypto || f.HasCryptoMarker {
		return ReporterCriptoExchange
	}
	if k == KindBienesPersonales {
		return ReporterOther
	}
	if k == KindGananciasRetenciones && f.HasGanancias {
		return ReporterALYC
	}
	if k == KindRG5193Daily {
		return ReporterALYC
	}
	if f.ReporterCuitRaw != "" {
		if p, _ := CuitFingerprint(f.ReporterCuitRaw); IsJuridicalCuitPrefix(p) {
			return ReporterALYC
		}
	}
	return ReporterUnknown
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{
		"Public", "Default", "Default User", "All Users", "Shared",
	} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
