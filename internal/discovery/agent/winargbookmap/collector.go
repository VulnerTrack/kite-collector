package winargbookmap

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

// fileCollector walks Bookmap install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbookmap" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BOOKMAP_DIR")); p != "" {
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
			for _, rel := range UserBookmapDirs() {
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
		BrokerPlugin: PluginUnknown,
		PeriodYYYYMM: PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".btr" || ext == ".jar" || ext == ".class"
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
	var fields BookmapFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseBookmapConfig(body)
	case KindWorkspace:
		fields = ParseBookmapWorkspace(body)
	case KindConnectionConfig:
		fields = ParseBookmapConnectionConfig(body)
	case KindIndicatorSDK:
		fields = ParseBookmapIndicatorSDK(body)
	case KindMarketplacePlugin:
		fields = ParseBookmapMarketplacePlugin(body)
	case KindSessionLog:
		fields = ParseBookmapSessionLog(body)
	case KindMBOCache:
		fields = ParseBookmapMBOCache(body)
	case KindBTRRecording, KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.APIKey != "" {
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.BookmapAccountID != "" {
		row.BookmapAccountID = fields.BookmapAccountID
	}
	if fields.HasSpeedOfTapeArmed {
		row.HasSpeedOfTapeArmed = true
	}
	if fields.HasMBOSubscription {
		row.HasMBOSubscription = true
		row.HasL3OrderbookData = true
	}
	if fields.BrokerPlugin != "" && fields.BrokerPlugin != PluginUnknown {
		row.BrokerPlugin = fields.BrokerPlugin
	}
	if fields.IndicatorCount > 0 {
		row.IndicatorCount = fields.IndicatorCount
	}
	if fields.MarketplaceCount > 0 {
		row.MarketplacePluginCount = fields.MarketplaceCount
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.MATbaSymbolsCount > 0 {
		row.MATbaSymbolsCount = fields.MATbaSymbolsCount
	}
	if fields.CMESymbolsCount > 0 {
		row.CMESymbolsCount = fields.CMESymbolsCount
	}
	if fields.CryptoSymbolsCount > 0 {
		row.CryptoSymbolsCount = fields.CryptoSymbolsCount
	}
	if fields.PeakMsgPerSec > 0 {
		row.PeakMsgPerSec = fields.PeakMsgPerSec
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyAccount picks the Bookmap account class. BTR
// recordings imply post-hoc order-flow research and must be
// checked BEFORE the generic L3 / MBO bucket — BTR is a
// stored replay (researcher), whereas live MBO subscription
// implies HFT execution.
func classifyAccount(r Row) AccountClass {
	if r.PeakMsgPerSec >= HighMessageRateThreshold ||
		r.HasSpeedOfTapeArmed {
		return AccountHFT
	}
	if r.HasBTRRecording {
		return AccountOrderFlowResearcher
	}
	if r.HasMBOSubscription || r.HasL3OrderbookData {
		return AccountHFT
	}
	if r.HasIndicatorSDK || r.HasMarketplacePlugin {
		return AccountAlgotrader
	}
	if r.HasCrossVenueArb {
		return AccountScalper
	}
	if r.HasCMEFutures || r.HasCryptoData {
		return AccountScalper
	}
	if r.HasBrokerPluginCredentials || r.HasPasswordInConfig {
		return AccountPropTrader
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	if r.HasSpeedOfTapeArmed || r.PeakMsgPerSec >= HighMessageRateThreshold {
		return ProductHFTExecution
	}
	venueCount := 0
	for _, b := range []bool{
		r.HasMATbaRofexRouting, r.HasCMEFutures,
		r.HasCryptoData,
	} {
		if b {
			venueCount++
		}
	}
	if venueCount >= 2 {
		return ProductMultiVenue
	}
	switch {
	case r.HasMATbaRofexRouting:
		return ProductMATbaRofex
	case r.HasCMEFutures:
		return ProductCMEFutures
	case r.HasCryptoData:
		return ProductCrypto
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
