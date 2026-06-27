package winargbyma

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

// fileCollector walks BYMA install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbyma" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BYMA_DIR")); p != "" {
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
			for _, rel := range UserBYMADirs() {
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
		Terminal:     TerminalFromPath(path),
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	if row.Terminal == TerminalUnknown {
		// Derive from artifact kind so back-office / blotter
		// files don't get TerminalUnknown when path lacks the
		// /edge/ /aries/ token (e.g. flat C:\BYMA\).
		switch row.ArtifactKind {
		case KindEdgeConfig:
			row.Terminal = TerminalEdge
		case KindAriesConfig:
			row.Terminal = TerminalAries
		case KindSXConfig:
			row.Terminal = TerminalSXBursatil
		case KindConnectAPI:
			row.Terminal = TerminalConnectAPI
		case KindLiquidacionT2, KindBCV:
			row.Terminal = TerminalBackOffice
		case KindRVBlotter, KindCEDEARPos, KindCaucionRV,
			KindMarketDataCache, KindInstaller, KindOther,
			KindUnknown:
			row.Terminal = TerminalOther
		}
	}
	if mat := MatriculaFromText(filepath.Base(path)); mat != "" {
		row.BrokerMatricula = mat
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		if IsOperatorCuitPrefix(prefix) {
			row.OperatorCuitPrefix = prefix
			row.OperatorCuitSuffix4 = suffix
		} else {
			row.ClienteCuitPrefix = prefix
			row.ClienteCuitSuffix4 = suffix
		}
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
	var fields BYMAFields
	switch row.ArtifactKind {
	case KindEdgeConfig, KindAriesConfig, KindSXConfig,
		KindConnectAPI:
		fields = ParseBYMAConfig(body)
	case KindRVBlotter, KindCEDEARPos, KindBCV,
		KindLiquidacionT2, KindCaucionRV:
		fields = ParseBYMABlotter(body)
	case KindMarketDataCache, KindInstaller, KindOther,
		KindUnknown:
		return
	}

	if fields.HasAPIKey {
		row.HasAPIKeyInConfig = true
		row.APIKeyHash = fields.APIKeyHash
	}
	if fields.HasMEPCCLArbitrage {
		row.HasMEPCCLArbitrage = true
	}
	if row.BrokerMatricula == "" && fields.BrokerMatricula != "" {
		row.BrokerMatricula = fields.BrokerMatricula
	}
	if row.OperatorCuitPrefix == "" && fields.OperatorCuitRaw != "" {
		if p, s := CuitFingerprint(fields.OperatorCuitRaw); p != "" {
			if IsOperatorCuitPrefix(p) {
				row.OperatorCuitPrefix = p
				row.OperatorCuitSuffix4 = s
			} else {
				row.ClienteCuitPrefix = p
				row.ClienteCuitSuffix4 = s
			}
		}
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
	if row.PeriodYYYYMM == "" && fields.Period != "" {
		if p := PeriodFromFilename("x_" + fields.Period); p != "" {
			row.PeriodYYYYMM = p
		}
	}
	row.TradeCount = fields.TradeCount
	row.CEDEARTickerCount = fields.CEDEARCount
	row.SovereignTickerCount = fields.SovereignCount
	row.DistinctTickerCount = fields.DistinctCount
	if fields.MaxNotionalCents > 0 {
		row.MaxPositionARSCents = fields.MaxNotionalCents
	}
	if fields.TotalCents > 0 {
		row.TotalPositionARSCents = fields.TotalCents
	}
	if fields.MaxPositionPct > 0 {
		row.MaxPositionPct = fields.MaxPositionPct
	}
	if fields.CaucionMaxTenorDays > 0 {
		row.CaucionMaxTenorDays = fields.CaucionMaxTenorDays
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
