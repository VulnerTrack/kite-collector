package winargamibroker

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

// fileCollector walks AmiBroker install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargamibroker" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AMIBROKER_DIR")); p != "" {
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
			for _, rel := range UserAmiBrokerDirs() {
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
		ext == ".dmg" || ext == ".adat" || ext == ".dll"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body, base)
		}
	} else if skipBody {
		if ext == ".dll" {
			// We still want to classify the plug-in by filename
			// even though we don't hash the binary body.
			fields := ParseAmiBrokerPlugin(nil, base)
			if fields.PluginDLLName != "" {
				row.PluginDLLName = fields.PluginDLLName
				row.BrokerPlugin = fields.BrokerPlugin
			}
		}
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

func (c *fileCollector) mergeFields(row *Row, body []byte, name string) {
	var fields AmiFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseAmiConfig(body)
	case KindAFLFormula:
		fields = ParseAmiAFLFormula(body)
	case KindAPXProject:
		fields = ParseAmiAPXProject(body)
	case KindWorkspace:
		fields = ParseAmiWorkspace(body)
	case KindLayout:
		fields = ParseAmiLayout(body)
	case KindAutotradeConfig:
		fields = ParseAmiAutotradeConfig(body)
	case KindBacktestReport:
		fields = ParseAmiBacktestReport(body)
	case KindTradeLog:
		fields = ParseAmiTradeLog(body)
	case KindBrokerPlugin:
		fields = ParseAmiBrokerPlugin(body, name)
	case KindADATDatabase, KindInstaller, KindOther, KindUnknown:
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
	if fields.HasBrokerPluginCreds {
		row.HasBrokerPluginCredentials = true
	}
	if fields.HasAutotradeArmed {
		row.HasAutotradeArmed = true
	}
	if fields.HasMERVStrategy {
		row.HasMERVStrategy = true
	}
	if fields.PluginDLLName != "" {
		row.PluginDLLName = fields.PluginDLLName
	}
	if fields.BrokerPlugin != "" && fields.BrokerPlugin != PluginUnknown {
		row.BrokerPlugin = fields.BrokerPlugin
	}
	if fields.OrderStatementCount > 0 {
		row.OrderStatementCount = fields.OrderStatementCount
	}
	if fields.FillCount > 0 {
		row.FillCount = fields.FillCount
	}
	if fields.DistinctTickers > 0 {
		row.DistinctTickersCount = fields.DistinctTickers
	}
	if fields.BYMATickersCount > 0 {
		row.BYMATickersCount = fields.BYMATickersCount
	}
	if fields.CEDEARTickersCount > 0 {
		row.CEDEARTickersCount = fields.CEDEARTickersCount
	}
	if fields.ARBondTickersCount > 0 {
		row.ARBondTickersCount = fields.ARBondTickersCount
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyAccount picks the AmiBroker account class.
func classifyAccount(r Row) AccountClass {
	if r.HasAutotradeArmed && r.HasAFLWithOrders {
		return AccountAlgotrader
	}
	if r.HasAutotradeArmed {
		return AccountAlgotrader
	}
	if r.ArtifactKind == KindAFLFormula && r.OrderStatementCount > 0 {
		return AccountAlgotrader
	}
	if r.ArtifactKind == KindBacktestReport ||
		r.ArtifactKind == KindAFLFormula {
		return AccountBacktestResearcher
	}
	if r.HasLiveTradeLog {
		return AccountEquityDaytrader
	}
	if r.HasBYMAEquity || r.HasCEDEAR || r.HasARBond {
		return AccountEquityDaytrader
	}
	if r.HasPasswordInConfig || r.HasBrokerPluginCredentials {
		return AccountEquityDaytrader
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	byma := r.BYMATickersCount > 0
	cedear := r.CEDEARTickersCount > 0
	bond := r.ARBondTickersCount > 0
	merv := r.HasMERVStrategy

	count := 0
	for _, b := range []bool{byma, cedear, bond, merv} {
		if b {
			count++
		}
	}
	if count >= 2 {
		return ProductMultiAsset
	}
	switch {
	case merv:
		return ProductMERVIndex
	case byma:
		return ProductBYMAEquity
	case cedear:
		return ProductARCEDEARs
	case bond:
		return ProductARBonds
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
