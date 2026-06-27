package winargcohen

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

// fileCollector walks Cohen install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcohen" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("COHEN_DIR")); p != "" {
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
			for _, rel := range UserCohenDirs() {
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
		FilePath:          path,
		FileSize:          fi.Size(),
		FileMode:          int(fi.Mode().Perm()),
		FileOwnerUID:      ownerUID(fi),
		UserProfile:       user,
		ArtifactKind:      ArtifactKindFromName(base),
		AccountClass:      AccountUnknown,
		ProductClass:      ProductUnknown,
		BackofficeChannel: BackofficeUnknown,
		PeriodYYYYMM:      PeriodFromFilename(base),
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
	row.AccountClass = classifyAccount(row)
	row.ProductClass = classifyProduct(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields CohenFields
	switch row.ArtifactKind {
	case KindProfile:
		fields = ParseCohenProfile(body)
	case KindSessionToken:
		fields = ParseCohenSessionToken(body)
	case KindMobileOAuth:
		fields = ParseCohenMobileOAuth(body)
	case KindFCISubscription:
		fields = ParseCohenFCISubscription(body)
	case KindFCIRedemption:
		fields = ParseCohenFCIRedemption(body)
	case KindCuotaparteRecord:
		fields = ParseCohenCuotaparte(body)
	case KindLiquidacionPDF:
		fields = ParseCohenLiquidacion(body)
	case KindResearchPDF:
		fields = ParseCohenResearch(body)
	case KindSAGGMConfig:
		fields = ParseCohenSAGGM(body)
	case KindFIXSession:
		fields = ParseCohenFIXSession(body)
	case KindTradeConfirmation:
		fields = ParseCohenTradeConfirmation(body)
	case KindStatement:
		fields = ParseCohenStatement(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInProfile = true
	}
	if fields.HasOAuth {
		row.HasOAuthRefreshToken = true
	}
	if fields.OAuthToken != "" {
		row.OAuthTokenHash = HashSecret(fields.OAuthToken)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.CuentaComitente != "" {
		row.CuentaComitente = fields.CuentaComitente
	}
	if fields.FIXSenderCompID != "" {
		row.FIXSenderCompID = fields.FIXSenderCompID
	}
	if fields.BackofficeChannel != "" && fields.BackofficeChannel != BackofficeUnknown {
		row.BackofficeChannel = fields.BackofficeChannel
	}
	if fields.CuotaparteCount > 0 {
		row.CuotaparteCount = fields.CuotaparteCount
	}
	if fields.LiquidacionCount > 0 {
		row.LiquidacionCount = fields.LiquidacionCount
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.AREquitySymbolsCount > 0 {
		row.AREquitySymbolsCount = fields.AREquitySymbolsCount
	}
	if fields.CEDEARSymbolsCount > 0 {
		row.CEDEARSymbolsCount = fields.CEDEARSymbolsCount
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyAccount picks the Cohen account class.
//
// Order matters:
//
//  1. Compliance officer (SAGGM back-office or FIX session
//     credentials = broker-wide exposure).
//  2. Institutional cliente (cuotaparte >= 1000 = class share).
//  3. FCI cuotapartista (subscription/redemption/cuotaparte).
//  4. FIX counterparty (FIX session without SAGGM).
//  5. Equity research subscriber (research PDFs).
//  6. Retail cliente (profile / OAuth / liquidación).
//  7. API (token without profile context).
func classifyAccount(r Row) AccountClass {
	if r.HasSAGGMBackoffice {
		return AccountComplianceOfficer
	}
	if r.HasInstitutionalClass {
		return AccountInstitutionalCliente
	}
	if r.HasFCISubscription || r.HasFCIRedemption || r.HasCuotaparteRecord {
		return AccountFCICuotapartista
	}
	if r.HasFIXSession {
		return AccountFIXCounterparty
	}
	if r.HasResearchPDF {
		return AccountEquityResearchSubscriber
	}
	if r.HasOAuthRefreshToken || r.HasPasswordInProfile ||
		r.HasLiquidacionPDF || r.HasCuentaComitente {
		return AccountRetailCliente
	}
	if r.ArtifactKind == KindSessionToken {
		return AccountAPI
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
//
// AR equity AND CEDEAR present → multi-asset (a typical Cohen
// retail cliente trades both AR equity and CEDEAR for MEP/CCL
// dollar exposure).
func classifyProduct(r Row) ProductClass {
	switch {
	case r.AREquitySymbolsCount > 0 && r.CEDEARSymbolsCount > 0:
		return ProductMultiAsset
	case r.HasFCISubscription || r.HasFCIRedemption || r.HasCuotaparteRecord:
		return ProductARFCI
	case r.AREquitySymbolsCount > 0:
		return ProductAREquity
	case r.CEDEARSymbolsCount > 0:
		return ProductCEDEAR
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
