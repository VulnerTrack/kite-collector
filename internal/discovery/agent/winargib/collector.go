package winargib

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

// fileCollector walks IB install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargib" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("IB_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("IBKR_DIR")); p != "" {
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
			for _, rel := range UserIBDirs() {
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
		ProductClass: ProductUnknown,
		PeriodYYYYMM: PeriodFromFilename(base),
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
	var fields IBFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseIBConfig(body)
	case KindGatewayConfig:
		fields = ParseIBGatewayConfig(body)
	case KindTWSSettings:
		fields = ParseIBTWSSettings(body)
	case KindPositions:
		fields = ParseIBPositions(body)
	case KindOrders:
		fields = ParseIBOrders(body)
	case KindStrategyPy:
		fields = ParseIBStrategyPy(body)
	case KindTradeLog:
		fields = ParseIBTradeLog(body)
	case KindFlexQuery:
		fields = ParseIBFlexQuery(body)
	case KindTaxStatement:
		fields = ParseIBTaxStatement(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasAPIExposed {
		row.HasAPISocketExposed = true
	}
	if fields.HasLive {
		row.HasLiveAccount = true
	}
	if fields.APISocketAddress != "" {
		row.APISocketAddress = fields.APISocketAddress
	}
	if fields.APISocketPort > 0 {
		row.APISocketPort = fields.APISocketPort
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.IBAccountSuffix4 != "" {
		row.IBAccountSuffix4 = fields.IBAccountSuffix4
	}
	if fields.HasUSEquity {
		row.HasUSEquityPositions = true
	}
	if fields.HasGlobalEquity {
		row.HasGlobalEquityPositions = true
	}
	if fields.HasFutures {
		row.HasFuturesCME = true
	}
	if fields.HasForex {
		row.HasForexTrading = true
	}
	if fields.HasCrypto {
		row.HasCryptoPositions = true
	}
	if fields.HasFlexExport {
		row.HasFlexQueryExport = true
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.PortfolioAUMUSDCents > 0 {
		row.PortfolioAUMUSDCents = fields.PortfolioAUMUSDCents
	}
	if fields.AboveCapCount > 0 {
		row.AboveCapCount = fields.AboveCapCount
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	row.AccountClass = classifyAccount(*row, fields)
	row.ProductClass = classifyProduct(fields)
}

// classifyAccount picks the IB account class from row + fields.
func classifyAccount(r Row, f IBFields) AccountClass {
	if f.APISocketPort > 0 {
		if class := PortToAccountClass(f.APISocketPort); class != AccountUnknown {
			return class
		}
	}
	if r.ArtifactKind == KindStrategyPy {
		return AccountAPI
	}
	if f.HasLive {
		return AccountRetail
	}
	if f.Username != "" || r.HasPasswordInConfig {
		return AccountRetail
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(f IBFields) ProductClass {
	count := 0
	var single ProductClass
	if f.HasUSEquity {
		count++
		single = ProductUSEquity
	}
	if f.HasGlobalEquity {
		count++
		single = ProductGlobalEquity
	}
	if f.HasFutures {
		count++
		single = ProductFuturesCME
	}
	if f.HasForex {
		count++
		single = ProductForex
	}
	if f.HasCrypto {
		count++
		single = ProductCrypto
	}
	if count == 0 {
		return ProductUnknown
	}
	if count > 1 {
		return ProductMultiAsset
	}
	return single
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
