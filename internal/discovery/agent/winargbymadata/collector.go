package winargbymadata

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

// fileCollector walks Bymadata install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbymadata" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BYMADATA_DIR")); p != "" {
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
			for _, rel := range UserBymadataDirs() {
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
		FilePath:         path,
		FileSize:         fi.Size(),
		FileMode:         int(fi.Mode().Perm()),
		FileOwnerUID:     ownerUID(fi),
		UserProfile:      user,
		ArtifactKind:     ArtifactKindFromName(base),
		AccountClass:     AccountUnknown,
		SubscriptionTier: TierUnknown,
		PeriodYYYYMM:     PeriodFromFilename(base),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".parquet" || ext == ".jar"
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
	var fields BymadataFields
	switch row.ArtifactKind {
	case KindCredentials, KindConfig, KindTerminalConfig:
		fields = ParseBymadataCredentials(body)
	case KindFIXFASTLog:
		fields = ParseBymadataFIXFASTLog(body)
	case KindWSLog:
		fields = ParseBymadataWSLog(body)
	case KindRESTCache:
		fields = ParseBymadataRESTCache(body)
	case KindHistoricalCSV:
		fields = ParseBymadataHistoricalCSV(body)
	case KindSDKScript:
		fields = ParseBymadataSDKScript(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.Tier != "" && fields.Tier != TierUnknown {
		row.SubscriptionTier = fields.Tier
	}
	if fields.APIKey != "" {
		row.HasAPIKey = true
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasFIXFASTSession {
		row.HasFIXFASTSession = true
	}
	if fields.HasWebsocketSession {
		row.HasWebsocketSession = true
	}
	if fields.HasDepthOfBook {
		row.HasDepthOfBook = true
	}
	if fields.HasInternational {
		row.HasInternationalTier = true
	}
	if fields.FIXSenderCompID != "" {
		row.FIXSessionSender = fields.FIXSenderCompID
	}
	if fields.FIXTargetCompID != "" {
		row.FIXSessionTarget = fields.FIXTargetCompID
	}
	if fields.SessionFirstSeen != "" {
		row.SessionFirstSeen = fields.SessionFirstSeen
	}
	if fields.SessionLastSeen != "" {
		row.SessionLastSeen = fields.SessionLastSeen
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolsCount = fields.DistinctSymbols
	}
	if fields.DistinctCuits > 0 {
		row.DistinctCuitCount = fields.DistinctCuits
		if row.LicenseeCuitPrefix == "" {
			if p, s := CuitFingerprint(string(body)); p != "" {
				row.LicenseeCuitPrefix = p
				row.LicenseeCuitSuffix4 = s
			}
		}
	}
	if fields.MessageCount > 0 {
		row.MessageCount = fields.MessageCount
	}
	if fields.PeakMsgPerSec > 0 {
		row.PeakMsgPerSec = fields.PeakMsgPerSec
	}
	if fields.HistoricalRows > 0 {
		row.HistoricalRowsCount = fields.HistoricalRows
	}
	row.AccountClass = classifyAccount(row.ArtifactKind, fields)
}

// classifyAccount picks an account-class from parsed fields.
func classifyAccount(k ArtifactKind, f BymadataFields) AccountClass {
	if f.HasFIXFASTSession {
		return AccountVendor
	}
	if f.HasDepthOfBook && f.HasWebsocketSession {
		return AccountMarketMaker
	}
	if f.HasInternational {
		return AccountFCIManager
	}
	if k == KindSDKScript {
		return AccountQuant
	}
	if f.HasWebsocketSession {
		return AccountRetailAggregator
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
