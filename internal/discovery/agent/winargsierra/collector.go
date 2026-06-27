package winargsierra

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

// fileCollector walks Sierra Chart install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargsierra" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SIERRA_DIR")); p != "" {
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
			for _, rel := range UserSierraDirs() {
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
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".dll" ||
		ext == ".scid" || ext == ".dly"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody {
		// For .scid/.dly/.dll/installers we just hash the file
		// (or skip the read entirely if too large).
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
	var fields SierraFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseSierraConfig(body)
	case KindWorkspace:
		fields = ParseSierraWorkspace(body)
	case KindChartbook:
		fields = ParseSierraChartbook(body)
	case KindACSILSource:
		fields = ParseSierraACSILSource(body)
	case KindSpreadsheet:
		fields = ParseSierraSpreadsheet(body)
	case KindTradingActivity:
		fields = ParseSierraTradingActivity(body)
	case KindDTCLog:
		fields = ParseSierraDTCLog(body)
	case KindSCIDTick, KindDLYDaily, KindACSILModule,
		KindInstaller, KindOther, KindUnknown:
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
	if fields.SierraAccountID != "" {
		row.SierraAccountID = fields.SierraAccountID
	}
	if fields.HasDTCSession {
		row.HasDTCSession = true
	}
	if fields.HasDTCServerURL {
		row.HasDTCServerURL = true
		if fields.DTCServerHost != "" {
			row.DTCServerHost = fields.DTCServerHost
		}
		if fields.DTCServerPort > 0 {
			row.DTCServerPort = fields.DTCServerPort
		}
	}
	if fields.HasAutotrade {
		row.HasSpreadsheetAutotrade = true
	}
	if fields.FillCount > 0 {
		row.FillCount = fields.FillCount
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

// classifyAccount picks the Sierra Chart account class.
func classifyAccount(r Row) AccountClass {
	if r.PeakMsgPerSec >= HighMessageRateThreshold ||
		r.HasACSILNativeModule {
		return AccountHFT
	}
	if r.HasSpreadsheetAutotrade {
		return AccountPropTrader
	}
	if r.MATbaSymbolsCount > 0 && r.CMESymbolsCount > 0 {
		return AccountArbitrageur
	}
	if r.ArtifactKind == KindACSILSource {
		return AccountQuantResearch
	}
	if r.MATbaSymbolsCount > 0 || r.CMESymbolsCount > 0 {
		return AccountProFutures
	}
	if r.HasPasswordInConfig || r.HasDTCServerURL {
		return AccountProFutures
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(r Row) ProductClass {
	matba := r.MATbaSymbolsCount > 0
	cme := r.CMESymbolsCount > 0
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		return ProductHFTExecution
	}
	switch {
	case matba && cme:
		return ProductMultiVenue
	case matba:
		return ProductMATbaRofex
	case cme:
		return ProductCMEFutures
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
