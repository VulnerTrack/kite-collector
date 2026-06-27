package winarglean

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

// fileCollector walks LEAN install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winarglean" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("LEAN_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("QUANTCONNECT_DIR")); p != "" {
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
			for _, rel := range UserLeanDirs() {
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
		AlgorithmClass:   ClassUnknown,
		DeploymentTarget: TargetUnknown,
		PeriodYYYYMM:     PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".zip"
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
	var fields LeanFields
	switch row.ArtifactKind {
	case KindConfig:
		fields = ParseLeanConfig(body)
	case KindCredentials:
		fields = ParseLeanCredentials(body)
	case KindAlgorithmCS:
		fields = ParseLeanAlgorithmCS(body)
	case KindAlgorithmPy:
		fields = ParseLeanAlgorithmPy(body)
	case KindBacktestResult:
		fields = ParseLeanBacktestResult(body)
	case KindLiveConfig:
		fields = ParseLeanLiveConfig(body)
	case KindCLIConfig:
		fields = ParseLeanCLIConfig(body)
	case KindNodepacket:
		fields = ParseLeanNodepacket(body)
	case KindDataSubscription, KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.BrokerageKey != "" {
		row.HasBrokerageAPIKey = true
		row.BrokerageKeyHash = HashSecret(fields.BrokerageKey)
	}
	if fields.QCUserToken != "" {
		row.QCUserTokenHash = HashSecret(fields.QCUserToken)
	}
	if fields.AlgorithmName != "" {
		row.AlgorithmName = fields.AlgorithmName
	}
	if fields.Class != "" && fields.Class != ClassUnknown {
		row.AlgorithmClass = fields.Class
	}
	if fields.Resolution != "" && fields.Resolution != ResolutionUnknown {
		row.DataResolution = fields.Resolution
	}
	if fields.HasLiveMode {
		row.HasLiveDeployment = true
	}
	if fields.HasArgentine {
		row.HasArgentineBrokerage = true
	}
	if fields.HasCrypto {
		row.HasCryptoBrokerage = true
	}
	if fields.HasUSEquity {
		row.HasUSEquities = true
	}
	if row.AlgorithmClass == ClassFutures {
		row.HasFuturesSubscription = true
	}
	if fields.BacktestCount > 0 {
		row.BacktestCount = fields.BacktestCount
	}
	if fields.DistinctSymbols > 0 {
		row.DistinctSymbolCount = fields.DistinctSymbols
	}
	if fields.SharpeRatioBps != 0 {
		row.SharpeRatioBps = fields.SharpeRatioBps
	}
	if fields.AnnualReturnBps != 0 {
		row.AnnualReturnBps = fields.AnnualReturnBps
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	row.DeploymentTarget = classifyDeployment(fields)
}

// classifyDeployment maps the parsed brokerage + live-mode
// flag onto the pinned DeploymentTarget enum.
func classifyDeployment(f LeanFields) DeploymentTarget {
	if !f.HasLiveMode {
		if f.BrokerageName != "" {
			return TargetPaper
		}
		return TargetBacktest
	}
	if f.BrokerageName == "" {
		return TargetLiveOther
	}
	return DeploymentTargetFromBrokerage(f.BrokerageName)
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
