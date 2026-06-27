package winargcocoscapital

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

// fileCollector walks Cocos install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcocoscapital" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("COCOS_DIR")); p != "" {
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
			for _, rel := range UserCocosDirs() {
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
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ArtifactKind: ArtifactKindFromName(filepath.Base(path)),
		Environment:  EnvUnknown,
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pdf" ||
		ext == ".xlsx" || ext == ".xls" ||
		ext == ".db" || ext == ".sqlite" || ext == ".sqlite3"
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
	row.Environment = EnvironmentFromBody(body)
	if row.Environment == EnvUnknown {
		row.Environment = EnvOther
	}

	var fields CocosFields
	switch row.ArtifactKind {
	case KindCredentials, KindConfig:
		fields = ParseCocosCredentials(body)
	case KindOrdersCache:
		fields = ParseCocosOrdersCache(body)
	case KindPortfolioCache:
		fields = ParseCocosPortfolio(body)
	case KindUSDTTradeLog:
		fields = ParseCocosUSDTLog(body)
	case KindFCISubscriptions:
		fields = ParseCocosFCISubscriptions(body)
	case KindStrategyScript:
		fields = ParseCocosStrategy(body)
	case KindMarketDataCache, KindAccountExport, KindTaxReport,
		KindIndexedDB, KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.BearerToken != "" {
		row.HasBearerToken = true
		row.BearerTokenHash = HashSecret(fields.BearerToken)
	}
	if fields.RefreshToken != "" {
		row.HasRefreshToken = true
		row.RefreshTokenHash = HashSecret(fields.RefreshToken)
	}
	if fields.Username != "" {
		row.HasUsernamePassword = true
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.HasPassword {
		row.HasUsernamePassword = true
	}
	if fields.Has2FA {
		row.Has2FAToken = true
	}
	if fields.HasMEPCCLArbitrage {
		row.HasMEPCCLArbitrage = true
	}
	if fields.HasStrategyImport {
		row.HasStrategyScript = true
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.SessionFirstSeen == "" {
		row.SessionFirstSeen = fields.SessionFirstSeen
	}
	if fields.SessionLastSeen != "" {
		row.SessionLastSeen = fields.SessionLastSeen
	}
	row.OrderCount = fields.OrderCount
	row.PollsPerMinuteMax = fields.PollsPerMinMax
	row.PortfolioPositionCount = fields.PortfolioCount
	if fields.MaxPositionCents > 0 {
		row.MaxPositionARSCents = fields.MaxPositionCents
	}
	if fields.USDTVolumeCents > 0 {
		row.USDTVolumeARSCents = fields.USDTVolumeCents
	}
	if fields.FCISubscriptionCount > 0 {
		row.FCISubscriptionCount = fields.FCISubscriptionCount
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
