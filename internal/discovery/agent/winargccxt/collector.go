package winargccxt

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

// fileCollector walks CCXT install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargccxt" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CCXT_DIR")); p != "" {
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
			for _, rel := range UserCCXTDirs() {
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
		ExchangeClass: ClassUnknown,
		PeriodYYYYMM:  PeriodFromFilename(base),
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
	var fields CCXTFields
	switch row.ArtifactKind {
	case KindCredentials, KindConfig, KindExchangeKeys:
		fields = ParseCCXTConfig(body)
	case KindStrategyPy:
		fields = ParseCCXTStrategyPy(body)
	case KindArbitrageBot:
		fields = ParseCCXTArbitrageBot(body)
	case KindTradeLog:
		fields = ParseCCXTTradeLog(body)
	case KindBalanceSnapshot:
		fields = ParseCCXTBalanceSnapshot(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.ExchangeID != "" {
		row.ExchangeID = fields.ExchangeID
		row.ExchangeClass = ExchangeClassFor(fields.ExchangeID)
	}
	if fields.ExchangeKey != "" {
		row.HasExchangeAPIKey = true
		row.ExchangeKeyHash = HashSecret(fields.ExchangeKey)
	}
	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasArgentine {
		row.HasArgentineExchange = true
	}
	if fields.HasGlobal {
		row.HasGlobalExchange = true
	}
	if fields.HasDerivatives {
		row.HasDerivativesExchange = true
	}
	if fields.HasDEX {
		row.HasDEXIntegration = true
	}
	if fields.HasArbitrageBot {
		row.HasArbitrageBot = true
	}
	if fields.HasFundingRate {
		row.HasFundingRateStrategy = true
	}
	if fields.HasUSDTARSArbitrage && fields.HasArgentine && fields.HasGlobal {
		row.HasUSDTARSArbitrage = true
	} else if fields.HasUSDTARSArbitrage && row.ArtifactKind == KindArbitrageBot {
		row.HasUSDTARSArbitrage = true
	}
	if fields.StrategyName != "" {
		row.StrategyName = fields.StrategyName
	}
	if fields.DistinctExchanges > 0 {
		row.DistinctExchangeCount = fields.DistinctExchanges
	}
	if fields.TradeCount > 0 {
		row.TradeCount = fields.TradeCount
	}
	if fields.PeakAPICallsPerSec > 0 {
		row.PeakAPICallsPerSec = fields.PeakAPICallsPerSec
	}
	if fields.TotalUSDTVolumeCents > 0 {
		row.TotalUSDTVolumeCents = fields.TotalUSDTVolumeCents
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
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
