package winargtradingview

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

// fileCollector walks TradingView install roots + per-user
// dirs.
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

func (c *fileCollector) Name() string { return "winargtradingview" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("TRADINGVIEW_DIR")); p != "" {
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
			for _, rel := range UserTVDirs() {
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
		LinkedBroker: BrokerUnknown,
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe"
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
	switch row.ArtifactKind {
	case KindPineScript, KindIndicator:
		fields := ParseTVPineScript(body)
		row.HasPineStrategy = fields.HasStrategyFn
		row.StrategyName = fields.StrategyName
		row.PineVersion = fields.PineVersion
		if fields.APIKey != "" {
			row.HasAPIKeyInPine = true
			row.APIKeyHash = HashSecret(fields.APIKey)
		}
		row.ArgentineTickerCount = int64(len(fields.ArgentineTickers))
	case KindWebhookConfig, KindStrategyAlert, KindBrokerLink:
		fields := ParseTVWebhookConfig(body)
		if fields.WebhookURL != "" {
			row.WebhookURLHash = HashSecret(fields.WebhookURL)
		}
		if fields.HasWebhookSecret {
			row.HasWebhookWithSecret = true
			if fields.APIKey != "" {
				row.APIKeyHash = HashSecret(fields.APIKey)
			}
		}
		row.AlertCount = fields.AlertCount
		row.LinkedBroker = LinkedBrokerFromBody(body)
		if fields.ClienteCuitRaw != "" {
			if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
				row.ClienteCuitPrefix = p
				row.ClienteCuitSuffix4 = s
				row.HasAlertWithPII = true
			}
		}
	case KindWatchlist:
		fields := ParseTVWatchlist(body)
		row.WatchlistTickerCount = fields.WatchlistTickers
		row.ArgentineTickerCount = int64(len(fields.ArgentineTickers))
	case KindChartLayout, KindConfig, KindCache, KindInstaller,
		KindOther, KindUnknown:
		return
	}

	if row.LinkedBroker == BrokerUnknown {
		row.LinkedBroker = BrokerOther
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
