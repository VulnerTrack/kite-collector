package winargbcrasiscen

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

// fileCollector walks SISCEN install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbcrasiscen" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BCRA_SISCEN_DIR")); p != "" {
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
			for _, rel := range UserSISCENDirs() {
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
		FilePath:       path,
		FileSize:       fi.Size(),
		FileMode:       int(fi.Mode().Perm()),
		FileOwnerUID:   ownerUID(fi),
		UserProfile:    user,
		ArtifactKind:   ArtifactKindFromName(base),
		AccountClass:   AccountUnknown,
		ProductClass:   ProductUnknown,
		SISCENFormCode: SISCENFormFromName(base),
		PeriodYYYYMM:   PeriodFromFilename(base),
		ReportingDate:  ReportingDateFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".pfx" || ext == ".p12"
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
	var fields SISCENFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseSISCENConfig(body)
	case KindPortalToken:
		fields = ParseSISCENPortalToken(body)
	case KindPortalCert:
		return
	case KindReport:
		fields = ParseSISCENReport(body)
	case KindTemplate:
		fields = ParseSISCENTemplate(body)
	case KindRejectionLog:
		fields = ParseSISCENRejectionLog(body)
	case KindSourceDump:
		fields = ParseSISCENSourceDump(body)
	case KindArchive:
		fields = ParseSISCENArchive(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.PortalToken != "" {
		row.HasBCRAPortalToken = true
		row.PortalTokenHash = HashSecret(fields.PortalToken)
	}
	if fields.HasPortalToken {
		row.HasBCRAPortalToken = true
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.EntityCode != "" {
		row.EntityCode = fields.EntityCode
	}
	if fields.TradeRecordCount > 0 {
		row.TradeRecordCount = fields.TradeRecordCount
	}
	if fields.DistinctISINsCount > 0 {
		row.DistinctISINsCount = fields.DistinctISINsCount
	}
	if fields.DistinctClientesCount > 0 {
		row.DistinctClientesCount = fields.DistinctClientesCount
	}
	if fields.HighValueTradeCount > 0 {
		row.HighValueTradeCount = fields.HighValueTradeCount
	}
	if fields.RejectionRecordCount > 0 {
		row.RejectionRecordCount = fields.RejectionRecordCount
	}
	if fields.SovBondRecordCount > 0 {
		row.SovBondRecordCount = fields.SovBondRecordCount
	}
	if fields.CorpONRecordCount > 0 {
		row.CorpONRecordCount = fields.CorpONRecordCount
	}
	if fields.EquityRecordCount > 0 {
		row.EquityRecordCount = fields.EquityRecordCount
	}
	if fields.FCIRecordCount > 0 {
		row.FCIRecordCount = fields.FCIRecordCount
	}
	if fields.RepoRecordCount > 0 {
		row.RepoRecordCount = fields.RepoRecordCount
	}
	if fields.ForwardRecordCount > 0 {
		row.ForwardRecordCount = fields.ForwardRecordCount
	}
	if fields.SwapRecordCount > 0 {
		row.SwapRecordCount = fields.SwapRecordCount
	}
	if fields.HasForeignResident {
		row.HasForeignResident = true
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyAccount picks the SISCEN account class. Heuristic:
// entity-code prefix or filename hints — banks typically have
// entity codes < 100; ALYCs have higher codes; FCI mgrs have a
// different prefix range.
func classifyAccount(r Row) AccountClass {
	n := strings.ToLower(filepath.Base(r.FilePath))
	if strings.Contains(n, "fci") || strings.Contains(n, "cuotaparte") {
		if r.FCIRecordCount > 0 || r.HasFCICuotapartes {
			return AccountSociedadGerente
		}
	}
	if strings.Contains(n, "alyc") || strings.Contains(n, "broker") {
		return AccountALYC
	}
	if strings.Contains(n, "banco") || strings.Contains(n, "bank") {
		return AccountEntidadFinanciera
	}
	if strings.Contains(n, "fideicomiso") {
		return AccountAgenteFideicomiso
	}
	if r.HasFCICuotapartes {
		return AccountSociedadGerente
	}
	if r.HasRepoCaucion || r.HasForwardOps || r.HasSwapOps {
		return AccountEntidadFinanciera
	}
	if r.HasSovBonds || r.HasCorpON || r.HasBYMAEquity {
		return AccountALYC
	}
	if r.HasPasswordInConfig || r.HasBCRAPortalToken {
		return AccountEntidadFinanciera
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	count := 0
	for _, b := range []bool{
		r.HasSovBonds, r.HasCorpON, r.HasBYMAEquity,
		r.HasFCICuotapartes, r.HasRepoCaucion,
		r.HasForwardOps, r.HasSwapOps,
	} {
		if b {
			count++
		}
	}
	if count >= 2 {
		return ProductMultiProduct
	}
	switch {
	case r.HasSovBonds:
		return ProductSovBondsTrades
	case r.HasCorpON:
		return ProductCorpONTrades
	case r.HasBYMAEquity:
		return ProductEquityTrades
	case r.HasFCICuotapartes:
		return ProductFCICuotapartesTrades
	case r.HasRepoCaucion:
		return ProductRepoCaucion
	case r.HasForwardOps:
		return ProductForwardOps
	case r.HasSwapOps:
		return ProductSwapOps
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
