package winargninjatrader

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth. NT8 has a deep
// Documents/NinjaTrader 8/bin/Custom/Strategies tree.
const MaxWalkDepth = 8

// fileCollector walks NT8 install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargninjatrader" }

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
			for _, rel := range UserNTDirs() {
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
		ArtifactKind: ArtifactKindFromPath(path),
		AccountType:  AccountUnknown,
		BrokerRoute:  BrokerUnknown,
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".dll" ||
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

	// Account-type heuristic from path tokens.
	row.AccountType = accountTypeFromPath(path)

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	if row.ArtifactKind == KindInstaller ||
		row.ArtifactKind == KindUnknown {
		return
	}
	fields := ParseNTArtifact(body)
	if fields.AccountLogin != "" {
		id := fields.AccountLogin
		if len(id) > 4 {
			id = id[len(id)-4:]
		}
		row.AccountLoginSuffix4 = id
	}
	if fields.StrategyName != "" {
		row.StrategyName = fields.StrategyName
	}
	if fields.BrokerRoute != BrokerUnknown {
		row.BrokerRoute = fields.BrokerRoute
	}
	if row.BrokerRoute == BrokerUnknown {
		row.BrokerRoute = BrokerOther
	}
	if fields.InstrumentCount > 0 {
		row.InstrumentCount = fields.InstrumentCount
	}
	if fields.OptimizerIterations > 0 {
		row.OptimizerIterations = fields.OptimizerIterations
	}
	if fields.HasDataProviderLogin {
		row.HasDataProviderLogin = true
	}
	if fields.HasReplayDump {
		row.HasReplayDump = true
	}
	if fields.HasArgentineFutures {
		row.HasArgentineFutures = true
	}
}

// accountTypeFromPath classifies the account type from path
// tokens. NT8 default sim accounts: Sim101 / Sim404; replay
// lives in `db\replay\`; live-account paths usually have the
// broker name (e.g. `Rithmic_live`).
func accountTypeFromPath(path string) AccountType {
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "sim101") ||
		strings.Contains(lower, "sim404") ||
		strings.Contains(lower, "/sim/") ||
		strings.Contains(lower, "playback"):
		return AccountDemo
	case strings.Contains(lower, "/replay/") ||
		strings.Contains(lower, "market_replay") ||
		strings.Contains(lower, "marketreplay"):
		return AccountReplay
	case strings.Contains(lower, "continuous") ||
		strings.Contains(lower, "_cont.") ||
		strings.Contains(lower, "/cont/"):
		return AccountContinuousFutures
	case strings.Contains(lower, "live") ||
		strings.Contains(lower, "rithmic") ||
		strings.Contains(lower, "amp") ||
		strings.Contains(lower, "ibkr"):
		return AccountLive
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
