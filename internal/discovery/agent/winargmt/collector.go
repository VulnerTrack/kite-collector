package winargmt

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth. MetaTrader has
// deep AppData trees (Terminal/<id>/MQL4/Experts/...) so we
// allow extra depth here.
const MaxWalkDepth = 8

// fileCollector walks MetaTrader install roots + per-user
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

func (c *fileCollector) Name() string { return "winargmt" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("METATRADER_DIR")); p != "" {
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
			for _, rel := range UserMTDirs() {
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
		ArtifactKind: refineKindFromPath(path),
		Platform:     PlatformFromPath(path),
		BrokerClass:  BrokerUnknown,
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	if row.Platform == PlatformUnknown {
		row.Platform = PlatformOther
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".dll" || ext == ".ex4" || ext == ".ex5" ||
		ext == ".hst"
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

// refineKindFromPath uses the parent directory token to
// discriminate between EA / Indicator / Script when the file
// name alone doesn't carry the distinction (the MQL source
// extensions are shared).
func refineKindFromPath(path string) ArtifactKind {
	k := ArtifactKindFromName(filepath.Base(path))
	if k != KindMQ4Source && k != KindMQ5Source {
		return k
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	switch {
	case strings.Contains(lower, "/indicators/"):
		return KindIndicatorMQ
	case strings.Contains(lower, "/scripts/"):
		return KindScriptMQ
	}
	return k
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	switch row.ArtifactKind {
	case KindTerminalConfig, KindAccountConfig, KindBrokerServers:
		fields := ParseMTTerminalConfig(body)
		applyConfigFields(row, fields)
		// origin.txt is also classified as broker-servers; use
		// the simpler origin parser when the file looks like a
		// single-line hostname blob.
		if row.BrokerHostname == "" {
			origin := ParseMTOrigin(body)
			row.BrokerHostname = origin.BrokerHostname
		}
	case KindOptimizeReport, KindBacktestReport:
		fields := ParseMTOptimizeReport(body)
		row.EAName = fields.EAName
		row.OptimizerOOSDropoffPct = OOSDropoffPct(
			fields.OptimizerInSampleProfit,
			fields.OptimizerOutSampleProfit)
	case KindMQ4Source, KindMQ5Source, KindIndicatorMQ, KindScriptMQ:
		// MQL source — check for DLL #import directives.
		if IsMQLSourceImportingDLL(body) {
			row.HasDLLPlugin = true
		}
	case KindEX4Compiled, KindEX5Compiled, KindDLLPlugin,
		KindHistoryHST, KindInstaller, KindOther, KindUnknown:
		// No body fields to extract.
	}

	// Classification picks the most-specific broker class across
	// every hostname-shaped token in the body. A config that
	// names `Server=ftmo-demo` AND `DataServer=demo.ftmo.com`
	// should classify as prop-firm (FTMO), not just demo.
	if row.BrokerHostname != "" {
		row.BrokerClass = BrokerClassFromHost(row.BrokerHostname)
	}
	if best := bestBrokerClass(body); best != BrokerUnknown {
		if rank(best) > rank(row.BrokerClass) {
			row.BrokerClass = best
		}
	}
	if row.BrokerClass == BrokerUnknown {
		row.BrokerClass = BrokerOther
	}
}

// bestBrokerClass scans the body for hostname tokens and
// returns the most-specific classification found.
func bestBrokerClass(body []byte) BrokerClass {
	if len(body) == 0 {
		return BrokerUnknown
	}
	best := BrokerUnknown
	for _, m := range brokerHostExtractRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		cls := BrokerClassFromHost(string(m[1]))
		if rank(cls) > rank(best) {
			best = cls
		}
	}
	return best
}

// rank orders broker classes by specificity (prop-firm and
// arg-broker take precedence over offshore; offshore over
// demo).
func rank(b BrokerClass) int {
	switch b {
	case BrokerPropFirm:
		return 5
	case BrokerArgentine:
		return 4
	case BrokerOffshore:
		return 3
	case BrokerDemo:
		return 2
	case BrokerOther:
		return 1
	case BrokerUnknown:
		return 0
	}
	return 0
}

func applyConfigFields(row *Row, fields MTFields) {
	if fields.HasPassword {
		row.HasAccountPassword = true
	}
	if fields.HasSignalProvider {
		row.HasSignalProvider = true
	}
	if fields.AccountLogin != "" {
		id := fields.AccountLogin
		if len(id) > 4 {
			id = id[len(id)-4:]
		}
		row.AccountLoginSuffix4 = id
	}
	if fields.ServerName != "" {
		row.ServerName = fields.ServerName
	}
	if fields.BrokerHostname != "" {
		row.BrokerHostname = fields.BrokerHostname
	}
	if fields.EAName != "" {
		row.EAName = fields.EAName
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
