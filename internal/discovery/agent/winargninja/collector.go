package winargninja

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

// fileCollector walks NinjaTrader install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargninja" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("NINJATRADER_DIR")); p != "" {
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
			for _, rel := range UserNinjaDirs() {
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
	c.applyCompiledOnly(out)
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
		DataFeed:     FeedUnknown,
		PropFirm:     PropFirmUnknown,
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
	if row.ArtifactKind == KindCompiledDLL {
		row.FileHash = HashContents(body)
		return
	}
	var fields NinjaFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseNinjaConfig(body)
	case KindStrategy:
		fields = ParseNinjaStrategy(body)
	case KindIndicator:
		fields = ParseNinjaIndicator(body)
	case KindAddOn:
		fields = ParseNinjaAddOn(body)
	case KindWorkspace, KindChartTemplate, KindStrategyTemplate:
		fields = ParseNinjaWorkspace(body)
	case KindConnection:
		fields = ParseNinjaConnection(body)
	case KindTradePerformance:
		fields = ParseNinjaTradePerformance(body)
	case KindPropFirmConfig:
		fields = ParseNinjaPropFirmConfig(body)
	case KindLog:
		fields = ParseNinjaLog(body)
	case KindExportPackage, KindInstaller, KindCompiledDLL,
		KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasNinjaStrategy {
		row.HasNinjaScriptStrategy = true
	}
	if fields.HasNinjaIndicator {
		row.HasNinjaScriptIndicator = true
	}
	if fields.HasNinjaAddOn {
		row.HasNinjaScriptAddOn = true
	}
	if fields.HasApexProp {
		row.HasApexProp = true
	}
	if fields.HasTopstepXProp {
		row.HasTopstepXProp = true
	}
	if fields.HasEarn2TradeProp {
		row.HasEarn2TradeProp = true
	}
	if fields.HasPythonBridge {
		row.HasPythonBridge = true
	}
	if fields.APIKey != "" {
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.NinjaAccountID != "" {
		row.NinjaAccountID = fields.NinjaAccountID
	}
	if fields.DataFeed != "" && fields.DataFeed != FeedUnknown {
		row.DataFeed = fields.DataFeed
	}
	if fields.PropFirm != "" && fields.PropFirm != PropFirmUnknown {
		row.PropFirm = fields.PropFirm
	}
	if fields.EnterOrderCallCount > 0 {
		row.EnterOrderCallCount = fields.EnterOrderCallCount
	}
	if fields.AddOnCount > 0 {
		row.AddOnCount = fields.AddOnCount
	}
	if fields.FillCount > 0 {
		row.FillCount = fields.FillCount
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.FuturesSymbolsCount > 0 {
		row.FuturesSymbolsCount = fields.FuturesSymbolsCount
	}
	if fields.MicroFuturesCount > 0 {
		row.MicroFuturesSymbolsCount = fields.MicroFuturesCount
	}
	if fields.OptionsSymbolsCount > 0 {
		row.OptionsSymbolsCount = fields.OptionsSymbolsCount
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// applyCompiledOnly marks `.dll` rows whose source `.cs` is
// absent from the same dir. A compiled-only DLL is opaque code
// execution surface (T1078).
func (c *fileCollector) applyCompiledOnly(rows []Row) {
	csByDir := map[string]bool{}
	for _, r := range rows {
		if r.ArtifactKind == KindStrategy ||
			r.ArtifactKind == KindIndicator ||
			r.ArtifactKind == KindAddOn {
			csByDir[filepath.Dir(r.FilePath)] = true
		}
	}
	for i := range rows {
		if rows[i].ArtifactKind != KindCompiledDLL {
			continue
		}
		if !csByDir[filepath.Dir(rows[i].FilePath)] {
			rows[i].HasCompiledOnlyDLL = true
			AnnotateSecurity(&rows[i])
			rows[i].AccountClass = classifyAccount(rows[i])
			rows[i].ProductClass = classifyProduct(rows[i])
		}
	}
}

// classifyAccount picks the NinjaTrader account class.
//
// Order matters:
//
//  1. PDT first (regulator-defined).
//  2. Compliance officer (connection-cred holder, broker-wide).
//  3. Scalper (high volume).
//  4. Algotrader (NinjaScript strategy with order calls).
//  5. Prop-firm trainee (Apex / TopstepX / etc community marker).
//  6. Futures day trader (TradePerformance signal).
//  7. Prop trader (connection cred holder without firm marker).
//  8. API (compiled-only DLL or API token).
func classifyAccount(r Row) AccountClass {
	if r.HasPatternDayTrader {
		return AccountPatternDayTrader
	}
	if r.HasConnectionCredentials && r.HasPasswordInConfig {
		return AccountComplianceOfficer
	}
	if r.HasHighVolumeTrader {
		return AccountScalper
	}
	if r.HasNinjaScriptStrategy && r.EnterOrderCallCount > 0 {
		return AccountAlgotrader
	}
	if r.HasApexProp || r.HasTopstepXProp || r.HasEarn2TradeProp ||
		(r.PropFirm != "" && r.PropFirm != PropFirmUnknown &&
			r.PropFirm != PropFirmNone) {
		return AccountPropFirmTrainee
	}
	if r.HasTradePerformanceExport {
		return AccountFuturesDaytrader
	}
	if r.HasConnectionCredentials {
		return AccountPropTrader
	}
	if r.HasCompiledOnlyDLL || r.HasNinjaScriptAddOn {
		return AccountAPI
	}
	if r.HasPasswordInConfig {
		return AccountFuturesDaytrader
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	switch {
	case r.HasFutures && r.OptionsSymbolsCount > 0:
		return ProductMultiAsset
	case r.HasFutures:
		return ProductFutures
	case r.OptionsSymbolsCount > 0:
		return ProductOptions
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
