package winargpybacktest

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 8

// fileCollector walks backtest install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargpybacktest" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("PYBACKTEST_DIR")); p != "" {
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
			for _, rel := range UserBacktestDirs() {
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
		FilePath:      path,
		FileSize:      fi.Size(),
		FileMode:      int(fi.Mode().Perm()),
		FileOwnerUID:  ownerUID(fi),
		UserProfile:   user,
		ArtifactKind:  ArtifactKindFromName(filepath.Base(path)),
		Framework:     FrameworkFromPath(path),
		StrategyClass: ClassUnknown,
		PeriodYYYYMM:  PeriodFromFilename(filepath.Base(path)),
	}
	if row.Framework == FrameworkUnknown {
		row.Framework = FrameworkOther
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkl" ||
		ext == ".pickle" || ext == ".parquet" || ext == ".bcolz" ||
		ext == ".feather"
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
	if row.ArtifactKind == KindInstaller ||
		row.ArtifactKind == KindUnknown {
		return
	}
	fields := ParsePyBacktestArtifact(body)
	if fields.SharpeX100 != 0 {
		row.SharpeX100 = fields.SharpeX100
	}
	if fields.AnnualReturnPct != 0 {
		row.AnnualReturnPct = fields.AnnualReturnPct
	}
	if fields.MaxDrawdownPct != 0 {
		row.MaxDrawdownPct = fields.MaxDrawdownPct
	}
	if fields.TradeCount > 0 {
		row.TradeCount = fields.TradeCount
	}
	if fields.StrategyName != "" {
		row.StrategyName = fields.StrategyName
	}
	if fields.HasLookaheadBias {
		row.HasLookaheadBias = true
	}
	if fields.HasIpynbWithSecrets {
		row.HasIpynbWithSecrets = true
	}
	if fields.APIKey != "" {
		row.HasAPIKeyInCode = true
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if len(fields.ArgentineTickers) > 0 {
		row.ArgentineTickerCount = int64(len(fields.ArgentineTickers))
	}
	if cls := StrategyClassFromTickers(fields.ArgentineTickers); cls != ClassUnknown {
		row.StrategyClass = cls
	}
	if row.StrategyClass == ClassUnknown {
		row.StrategyClass = ClassOther
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
