package winargdas

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

// fileCollector walks DAS install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargdas" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("DAS_DIR")); p != "" {
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
			for _, rel := range UserDASDirs() {
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
		ClearingFirm: ClearingUnknown,
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
	var fields DASFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseDASConfig(body)
	case KindLayout:
		fields = ParseDASLayout(body)
	case KindHotKeys:
		fields = ParseDASHotKeys(body)
	case KindScript:
		fields = ParseDASScript(body)
	case KindRoute:
		fields = ParseDASRoute(body)
	case KindClearingConfig:
		fields = ParseDASClearingConfig(body)
	case KindOrderLog:
		fields = ParseDASOrderLog(body)
	case KindShortLocateLog:
		fields = ParseDASShortLocateLog(body)
	case KindAPIToken, KindMobileToken:
		fields = ParseDASAPIToken(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasDASInetRoute {
		row.HasDASInetRouting = true
	}
	if fields.APIKey != "" {
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.DASTraderID != "" {
		row.DASTraderID = fields.DASTraderID
	}
	if fields.ClearingFirm != "" && fields.ClearingFirm != ClearingUnknown {
		row.ClearingFirm = fields.ClearingFirm
	}
	if fields.PropFirm != "" && fields.PropFirm != PropFirmUnknown {
		row.PropFirm = fields.PropFirm
	}
	if fields.HotKeyCount > 0 {
		row.HotKeyCount = fields.HotKeyCount
	}
	if fields.ChordHotKeyCount > 0 {
		row.ChordHotKeyCount = fields.ChordHotKeyCount
	}
	if fields.ScriptSendOrderCount > 0 {
		row.ScriptSendOrderCount = fields.ScriptSendOrderCount
	}
	if fields.FillCount > 0 {
		row.FillCount = fields.FillCount
	}
	if fields.ShortLocateCount > 0 {
		row.ShortLocateCount = fields.ShortLocateCount
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.USEquitySymbolsCount > 0 {
		row.USEquitySymbolsCount = fields.USEquitySymbolsCount
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

// classifyAccount picks the DAS Trader account class.
//
// Order matters:
//
//  1. PDT first (regulator-defined).
//  2. Compliance officer (clearing-cred holder, sees firm-wide).
//  3. Scalper (chord-HotKeys + high volume).
//  4. Algotrader (DASScript automation).
//  5. Prop-firm trainee (community marker).
//  6. US equity day trader (orderlog / short-locate signal).
//  7. Prop trader (DAS Inet routing).
func classifyAccount(r Row) AccountClass {
	if r.HasPatternDayTrader {
		return AccountPatternDayTrader
	}
	if r.HasClearingCredentials {
		return AccountComplianceOfficer
	}
	if r.HasHighVolumeTrader || r.ChordHotKeyCount > 0 {
		return AccountScalper
	}
	if r.HasDASScript {
		return AccountPropTrader
	}
	if r.PropFirm != "" && r.PropFirm != PropFirmUnknown &&
		r.PropFirm != PropFirmNone {
		return AccountPropFirmTrainee
	}
	if r.HasShortLocateLog || r.HasOrderLogExport {
		return AccountUSEquityDaytrader
	}
	if r.HasDASInetRouting {
		return AccountPropTrader
	}
	if r.HasAPICredentials {
		return AccountAPI
	}
	if r.HasPasswordInConfig {
		return AccountUSEquityDaytrader
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	if r.HasOptionsChain && r.HasUSEquity {
		return ProductMultiAsset
	}
	switch {
	case r.HasOptionsChain:
		return ProductUSOptions
	case r.HasUSEquity:
		return ProductUSEquity
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
