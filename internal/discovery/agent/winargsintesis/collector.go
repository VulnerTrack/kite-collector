package winargsintesis

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

// fileCollector walks Sintesis install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargsintesis" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SINTESIS_DIR")); p != "" {
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
			for _, rel := range UserSintesisDirs() {
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
		AccountClass:  AccountUnknown,
		ProductClass:  ProductUnknown,
		PeriodYYYYMM:  PeriodFromFilename(base),
		ReportingDate: ReportingDateFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody {
		if fi.Size() <= MaxFileBytes {
			body, err := c.readFile(path)
			if err == nil {
				row.FileHash = HashContents(body)
			}
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	row.AccountClass = classifyAccount(row)
	row.ProductClass = classifyProduct(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields SintesisFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseSintesisConfig(body)
	case KindFCIDatabase:
		fields = ParseSintesisFCIDatabase(body)
	case KindNAVCalc:
		fields = ParseSintesisNAVCalc(body)
	case KindCuotaparteLedger:
		fields = ParseSintesisCuotaparteLedger(body)
	case KindSuscripcion:
		fields = ParseSintesisSuscripcion(body)
	case KindRescate:
		fields = ParseSintesisRescate(body)
	case KindBCRAA5273:
		fields = ParseSintesisBCRAA5273(body)
	case KindCNVHR:
		fields = ParseSintesisCNVHR(body)
	case KindValuationFile:
		fields = ParseSintesisValuationFile(body)
	case KindPagoRescate:
		fields = ParseSintesisPagoRescate(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasDBCredentials {
		row.HasDBCredentials = true
	}
	if fields.DBConnString != "" {
		row.DBConnHash = HashSecret(fields.DBConnString)
	}
	if fields.HasForeignResident {
		row.HasForeignResident = true
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.FCICode != "" {
		row.FCICode = fields.FCICode
	}
	if fields.SociedadGerenteCUIT != "" {
		row.SociedadGerenteCUIT = fields.SociedadGerenteCUIT
	}
	if fields.CuotapartistaCount > 0 {
		row.CuotapartistaCount = fields.CuotapartistaCount
	}
	if fields.DistinctFCIsCount > 0 {
		row.DistinctFCIsCount = fields.DistinctFCIsCount
	}
	if fields.NAVARSCents > 0 {
		row.NAVARSCents = fields.NAVARSCents
	}
	if fields.AUMUSDCents > 0 {
		row.AUMUSDCents = fields.AUMUSDCents
	}
	if fields.SuscripcionCount > 0 {
		row.SuscripcionCount = fields.SuscripcionCount
	}
	if fields.RescateCount > 0 {
		row.RescateCount = fields.RescateCount
	}
	if fields.MaxHolderPct > 0 {
		row.MaxHolderPct = fields.MaxHolderPct
	}
	if fields.PIISignalCount > 0 {
		row.PIISignalCount = fields.PIISignalCount
	}
	if fields.ClienteDNI != "" {
		row.ClienteDNIHash = HashSecret(fields.ClienteDNI)
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyAccount picks the Sintesis account class.
func classifyAccount(r Row) AccountClass {
	if r.HasCNVHRFiling || r.HasBCRAA5273Report ||
		r.HasClienteCuitExport {
		return AccountComplianceOfficer
	}
	if r.ArtifactKind == KindFCIDatabase ||
		r.ArtifactKind == KindCuotaparteLedger ||
		r.HasNAVCalcData {
		return AccountSociedadGerente
	}
	if r.HasPagoRescate ||
		r.ArtifactKind == KindSuscripcion ||
		r.ArtifactKind == KindRescate {
		return AccountOpsAdministrator
	}
	if r.HasDBCredentials || r.HasPasswordInConfig {
		return AccountSociedadGerente
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	if r.DistinctFCIsCount >= 2 {
		return ProductMultiFCI
	}
	n := strings.ToLower(filepath.Base(r.FilePath))
	switch {
	case strings.Contains(n, "money_market") ||
		strings.Contains(n, "money-market") ||
		strings.Contains(n, "ahorro_pesos") ||
		strings.Contains(n, "mercado_fondo"):
		return ProductFCIMoneyMarket
	case strings.Contains(n, "renta_variable") ||
		strings.Contains(n, "renta-variable") ||
		strings.Contains(n, "equity"):
		return ProductFCIRentaVariable
	case strings.Contains(n, "renta_fija") ||
		strings.Contains(n, "renta-fija") ||
		strings.Contains(n, "bonds"):
		return ProductFCIRentaFija
	case strings.Contains(n, "mixto"):
		return ProductFCIMixto
	case strings.Contains(n, "pyme"):
		return ProductFCIPyme
	case strings.Contains(n, "infrastructure") ||
		strings.Contains(n, "infraestructura"):
		return ProductFCIInfrastructure
	}
	return ProductUnknown
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
