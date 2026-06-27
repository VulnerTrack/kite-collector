package winalgotrading

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 8 // MetaTrader directories are deep

// fileCollector walks algotrading install roots + per-user
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

func (c *fileCollector) Name() string { return "winalgotrading" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("ALGOTRADING_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("QUICKFIX_DIR")); p != "" {
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
			if isSystemPseudoProfile(name) {
				continue
			}
			for _, rel := range UserAlgoDirs() {
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
	// Dedupe.
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
		Application:  ApplicationFromPath(path),
	}

	ext := strings.ToLower(filepath.Ext(path))
	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			switch row.ArtifactKind {
			case KindFIXConfig:
				fields := ParseFIXConfig(body)
				row.FIXSenderCompID = fields.SenderCompID
				row.FIXTargetCompID = fields.TargetCompID
				row.HasCredentialsInConfig = fields.HasCredentialsInline
			case KindFIXSessionLog:
				row.FIXRecordCount = CountFIXMessages(body)
			case KindJupyterNotebook:
				if ContainsAPIKey(body) {
					row.HasAPIKeyInNotebook = true
				}
			case KindAlgoConfig:
				if ContainsAPIKey(body) {
					row.HasCredentialsInConfig = true
				}
			case KindMT4EA, KindMT5EA, KindMQLSource,
				KindNinjaTraderStrategy, KindSQXStrategy,
				KindPythonPKL, KindOHLCVParquet,
				KindBacktestResult, KindOther, KindUnknown:
				// no specific content extraction
			}
			// Also scan compiled-EA bodies for stray creds.
			if ext == ".mq4" || ext == ".mq5" || ext == ".cs" {
				if ContainsAPIKey(body) {
					row.HasCredentialsInConfig = true
				}
			}
		}
	}

	if row.Application == AppUnknown {
		// Try filename-based fallback.
		switch row.ArtifactKind {
		case KindFIXConfig, KindFIXSessionLog:
			row.Application = AppQuickFIX
		case KindMT4EA, KindMQLSource:
			if ext == ".mq4" || ext == ".ex4" {
				row.Application = AppMetaTrader4
			}
		case KindMT5EA:
			row.Application = AppMetaTrader5
		case KindNinjaTraderStrategy:
			row.Application = AppNinjaTrader
		case KindSQXStrategy:
			row.Application = AppStrategyQuant
		case KindJupyterNotebook:
			row.Application = AppJupyterLab
		case KindPythonPKL, KindOHLCVParquet, KindAlgoConfig,
			KindBacktestResult, KindOther, KindUnknown:
			row.Application = AppCustomPython
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
