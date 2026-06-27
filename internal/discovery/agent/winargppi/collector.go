package winargppi

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

// fileCollector walks PPI install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargppi" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("PPI_DIR")); p != "" {
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
			for _, rel := range UserPPIDirs() {
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
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ArtifactKind: ArtifactKindFromName(base),
		AccountClass: AccountUnknown,
		PeriodYYYYMM: PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".xlsx" || ext == ".xls"
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
	var fields PPIFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParsePPICredentials(body)
	case KindPositionsCache:
		fields = ParsePPIPositions(body)
	case KindOrdersCache:
		fields = ParsePPIOrders(body)
	case KindWealthPortfolio:
		fields = ParsePPIWealthPortfolio(body)
	case KindCorporateTreasury:
		fields = ParsePPICorporateTreasury(body)
	case KindPerfilInversor:
		fields = ParsePPIPerfilInversor(body)
	case KindQuantScript:
		fields = ParsePPIQuantScript(body)
	case KindInternacional:
		fields = ParsePPIInternacional(body)
	case KindAccountExport:
		fields = ParsePPIAccountExport(body)
	case KindTaxStatement:
		fields = ParsePPITaxStatement(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.BearerToken != "" {
		row.HasBearerToken = true
		row.BearerTokenHash = HashSecret(fields.BearerToken)
	}
	if fields.GaliciaSSO != "" {
		row.HasGaliciaSSO = true
		row.GaliciaSSOHash = HashSecret(fields.GaliciaSSO)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.BrokerMatricula != "" {
		row.BrokerMatricula = fields.BrokerMatricula
	}
	if fields.HasWealthMarker {
		row.HasWealthPortfolio = true
	}
	if fields.HasCorporateMarker {
		row.HasCorporateTreasury = true
	}
	if fields.HasInternacionalMarker {
		row.HasInternationalAssets = true
	}
	if fields.HasQuantImport {
		row.HasQuantStrategy = true
	}
	if fields.HasPerfilInversorMarker {
		row.HasPerfilInversor = true
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.InternationalCount > 0 {
		row.InternationalPositionCount = fields.InternationalCount
	}
	if fields.CERUVACount > 0 {
		row.CERUVAPositionCount = fields.CERUVACount
	}
	if fields.PortfolioAUMUSDCents > 0 {
		row.PortfolioAUMUSDCents = fields.PortfolioAUMUSDCents
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	row.AccountClass = classifyAccount(*row, fields)
}

// classifyAccount picks an account class from row + fields.
func classifyAccount(r Row, f PPIFields) AccountClass {
	if r.ArtifactKind == KindQuantScript || f.HasQuantImport {
		return AccountAPI
	}
	if r.ArtifactKind == KindCorporateTreasury || f.HasCorporateMarker {
		return AccountCorporateTreasury
	}
	if r.ArtifactKind == KindWealthPortfolio || f.HasWealthMarker {
		return AccountWealth
	}
	if r.HasHighAUM {
		return AccountPrivateBanking
	}
	if r.ArtifactKind == KindInternacional || f.HasInternacionalMarker {
		return AccountRetail
	}
	if f.Username != "" || r.HasPasswordInConfig {
		return AccountRetail
	}
	return AccountUnknown
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
