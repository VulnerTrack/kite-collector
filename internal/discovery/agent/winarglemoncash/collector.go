package winarglemoncash

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

// fileCollector walks Lemon install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winarglemoncash" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("LEMON_DIR")); p != "" {
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
			for _, rel := range UserLemonDirs() {
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
	var fields LemonFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseLemonConfig(body)
	case KindSDKScript:
		fields = ParseLemonSDKScript(body)
	case KindTradeLog:
		fields = ParseLemonTradeLog(body)
	case KindEarnPositions:
		fields = ParseLemonEarnPositions(body)
	case KindKYCDump:
		fields = ParseLemonKYCDump(body)
	case KindCardTransactions:
		fields = ParseLemonCardTransactions(body)
	case KindArbitrageScript:
		fields = ParseLemonArbitrageScript(body)
	case KindMarketplaceConfig:
		fields = ParseLemonMarketplaceConfig(body)
	case KindWebhookConfig:
		fields = ParseLemonWebhookConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.AccessToken != "" {
		row.AccessTokenHash = HashSecret(fields.AccessToken)
		row.HasOAuthAccessToken = true
	}
	if fields.HasAccessToken {
		row.HasOAuthAccessToken = true
	}
	if fields.RefreshToken != "" {
		row.RefreshTokenHash = HashSecret(fields.RefreshToken)
		row.HasOAuthRefreshToken = true
	}
	if fields.HasRefreshToken {
		row.HasOAuthRefreshToken = true
	}
	if fields.WebhookSecret != "" {
		row.WebhookSecretHash = HashSecret(fields.WebhookSecret)
		row.HasMarketplaceWebhook = true
	}
	if fields.HasWebhookSecret {
		row.HasMarketplaceWebhook = true
	}
	if fields.HasSDKCredentials {
		row.HasSDKCredentials = true
	}
	if fields.HasUSDTARSArbitrage {
		row.HasUSDTARSArbitrage = true
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.LemonUserID != "" {
		row.LemonUserID = fields.LemonUserID
	}
	if fields.LemonAppID != "" {
		row.LemonAppID = fields.LemonAppID
	}
	if fields.CryptoBalanceUSDCents > 0 {
		row.CryptoBalanceUSDCents = fields.CryptoBalanceUSDCents
	}
	if fields.TradeRecordCount > 0 {
		row.TradeRecordCount = fields.TradeRecordCount
	}
	if fields.CardTxCount > 0 {
		row.CardTxCount = fields.CardTxCount
	}
	if fields.EarnPositionCount > 0 {
		row.EarnPositionCount = fields.EarnPositionCount
	}
	if fields.DistinctAssetsCount > 0 {
		row.DistinctAssetsCount = fields.DistinctAssetsCount
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

// classifyAccount picks the Lemon account class.
func classifyAccount(r Row) AccountClass {
	n := strings.ToLower(filepath.Base(r.FilePath))
	if strings.Contains(n, "compliance") ||
		r.HasKYCDump {
		return AccountComplianceOfficer
	}
	if strings.Contains(n, "marketplace") || r.HasMarketplaceWebhook {
		return AccountMerchant
	}
	if r.ArtifactKind == KindSDKScript ||
		r.ArtifactKind == KindArbitrageScript ||
		r.HasSDKCredentials {
		return AccountDeveloper
	}
	if r.HasTradeLog || r.HasEarnPositions || r.HasCardTransactions {
		return AccountConsumer
	}
	if r.HasOAuthAccessToken || r.HasOAuthRefreshToken {
		return AccountAPI
	}
	if r.HasPasswordInConfig {
		return AccountConsumer
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	count := 0
	for _, b := range []bool{
		r.HasTradeLog, r.HasEarnPositions, r.HasCardTransactions,
		r.HasUSDTARSArbitrage, r.HasMarketplaceWebhook,
	} {
		if b {
			count++
		}
	}
	if count >= 2 {
		return ProductMultiProduct
	}
	switch {
	case r.HasCardTransactions:
		return ProductCryptoCard
	case r.HasEarnPositions:
		return ProductYieldEarn
	case r.HasUSDTARSArbitrage:
		return ProductStablecoinRails
	case r.HasMarketplaceWebhook:
		return ProductMarketplace
	case r.HasTradeLog:
		return ProductCryptoWallet
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
