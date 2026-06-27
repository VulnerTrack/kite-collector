package winargfideicomiso

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

// fileCollector walks Fideicomiso install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargfideicomiso" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("FIDEICOMISO_DIR")); p != "" {
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
			for _, rel := range UserFFDirs() {
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
		FilePath:        path,
		FileSize:        fi.Size(),
		FileMode:        int(fi.Mode().Perm()),
		FileOwnerUID:    ownerUID(fi),
		UserProfile:     user,
		ArtifactKind:    ArtifactKindFromName(base),
		TrustRole:       RoleUnknown,
		UnderlyingClass: UnderlyingUnknown,
		ReportingPeriod: PeriodFromFilename(base),
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
	} else if skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	row.TrustRole = classifyRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields FFFields
	switch row.ArtifactKind {
	case KindProspecto:
		fields = ParseProspecto(body)
	case KindSuplementoSerie:
		fields = ParseSuplemento(body)
	case KindEscrituraFiduciaria:
		fields = ParseEscritura(body)
	case KindContratoFiduciario:
		fields = ParseContratoFiduciario(body)
	case KindCobranzaCSV:
		fields = ParseCobranzaCSV(body)
	case KindMoraCSV:
		fields = ParseMoraCSV(body)
	case KindPrecancelacionCSV:
		fields = ParsePrecancelacionCSV(body)
	case KindTituloSerie:
		fields = ParseTituloSerie(body)
	case KindInvestorList:
		fields = ParseInvestorList(body)
	case KindCalificacionReport:
		fields = ParseCalificacionReport(body)
	case KindAdministratorReport:
		fields = ParseAdministratorReport(body)
	case KindAuditReport:
		fields = ParseAuditReport(body)
	case KindFilingReceipt:
		fields = ParseFilingReceipt(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasPreIssuanceDraft {
		row.HasPreIssuanceDraft = true
	}
	if fields.SeriesID != "" {
		row.SeriesID = fields.SeriesID
	}
	if fields.CNVAuthorizationID != "" {
		row.CNVAuthorizationID = fields.CNVAuthorizationID
	}
	if fields.FFName != "" {
		row.FFNameHash = HashSecret(fields.FFName)
	}
	if fields.UnderlyingClass != "" && fields.UnderlyingClass != UnderlyingUnknown {
		row.UnderlyingClass = fields.UnderlyingClass
	}
	if fields.TrancheClass != "" && fields.TrancheClass != TrancheUnknown {
		row.TrancheClass = fields.TrancheClass
	}
	if fields.RatingClass != "" && fields.RatingClass != RatingUnknown {
		row.RatingClass = fields.RatingClass
	}
	if fields.ReceivableCount > 0 {
		row.ReceivableCount = fields.ReceivableCount
	}
	if fields.CollectionTotalARSMillions > 0 {
		row.CollectionTotalARSMillions = fields.CollectionTotalARSMillions
	}
	if fields.MoraCount > 0 {
		row.MoraCount = fields.MoraCount
	}
	if fields.MoraAmountARSMillions > 0 {
		row.MoraAmountARSMillions = fields.MoraAmountARSMillions
	}
	if fields.InvestorCount > 0 {
		row.InvestorCount = fields.InvestorCount
	}
	if fields.IssuanceAmountARSMillions > 0 {
		row.IssuanceAmountARSMillions = fields.IssuanceAmountARSMillions
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.OriginadorCuitPrefix == "" && fields.OriginadorCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.OriginadorCuitRaw); p != "" {
			row.OriginadorCuitPrefix = p
			row.OriginadorCuitSuffix4 = s
		}
	}
	if row.FiduciarioCuitPrefix == "" && fields.FiduciarioCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.FiduciarioCuitRaw); p != "" {
			row.FiduciarioCuitPrefix = p
			row.FiduciarioCuitSuffix4 = s
		}
	}
}

// classifyRole picks the trust role.
//
// Order:
//
//  1. Fiduciario (administrator report = fiduciario role).
//  2. Agente Control Revisión (audit report).
//  3. Servicer (cobranza / mora / precancelación = servicer role).
//  4. Originador (originador CUIT distinct from fiduciario).
//  5. Underwriter (titulo serie + investor list = primary).
//  6. Calificadora (rating report).
//  7. Custodio (titulo serie alone).
//  8. Compliance officer (filing receipt).
//  9. API (config without filing context).
func classifyRole(r Row) TrustRole {
	if r.HasAdministratorReport {
		return RoleFiduciario
	}
	if r.HasAuditReport {
		return RoleAgenteControlRevision
	}
	if r.HasCobranzaCSV || r.HasMoraCSV || r.HasPrecancelacionCSV {
		return RoleServicer
	}
	if r.HasOriginadorCuit && r.FiduciarioCuitPrefix == "" {
		return RoleOriginador
	}
	if r.HasInvestorList && r.HasTituloSerie {
		return RoleUnderwriter
	}
	if r.HasInvestorList {
		return RoleColocador
	}
	if r.HasCalificacionReport {
		return RoleCalificadora
	}
	if r.HasTituloSerie {
		return RoleCustodio
	}
	if r.ArtifactKind == KindFilingReceipt {
		return RoleComplianceOfficer
	}
	if r.ArtifactKind == KindConfig || r.ArtifactKind == KindCredentials {
		return RoleAPI
	}
	return RoleUnknown
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
