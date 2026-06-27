package winargcqg

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

// fileCollector walks CQG install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcqg" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CQG_DIR")); p != "" {
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
			for _, rel := range UserCQGDirs() {
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
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg"
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
	var fields CQGFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseCQGConfig(body)
	case KindICConfig:
		fields = ParseCQGICConfig(body)
	case KindQTraderConfig:
		fields = ParseCQGQTraderConfig(body)
	case KindContinuumConfig:
		fields = ParseCQGContinuumConfig(body)
	case KindAlgoSEStrategy:
		fields = ParseCQGAlgoSEStrategy(body)
	case KindAPIScript:
		fields = ParseCQGAPIScript(body)
	case KindSessionLog:
		fields = ParseCQGSessionLog(body)
	case KindPositions:
		fields = ParseCQGPositions(body)
	case KindOrders:
		fields = ParseCQGOrders(body)
	case KindFIXLog:
		fields = ParseCQGFIXLog(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.APIKey != "" {
		row.HasAPICredentials = true
		row.APIKeyHash = HashSecret(fields.APIKey)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.CQGAccountID != "" {
		row.CQGAccountID = fields.CQGAccountID
	}
	if fields.FIXSenderCompID != "" {
		row.FIXSenderCompID = fields.FIXSenderCompID
	}
	if fields.FIXTargetCompID != "" {
		row.FIXTargetCompID = fields.FIXTargetCompID
	}
	if fields.HasFIXContinuum {
		row.HasContinuumFIXSession = true
	}
	if fields.HasFIXDropCopy {
		row.HasFIXDropCopy = true
	}
	if fields.HasAlgoSEMarker {
		row.HasAlgoSEStrategy = true
	}
	if fields.HasQTraderMarker {
		row.HasBlockQTrader = true
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
	if fields.BlockTradeCount > 0 {
		row.BlockTradeCount = fields.BlockTradeCount
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
	row.AccountClass = classifyAccount(*row, fields)
	row.ProductClass = classifyProduct(fields)
}

// classifyAccount picks the CQG account class.
func classifyAccount(r Row, f CQGFields) AccountClass {
	if r.ArtifactKind == KindAPIScript || r.ArtifactKind == KindAlgoSEStrategy {
		return AccountAPI
	}
	if f.HasFIXContinuum || f.HasFIXDropCopy {
		return AccountInstitutional
	}
	if f.MATbaSymbolsCount > 0 && f.CMESymbolsCount > 0 {
		return AccountArbitrageur
	}
	if f.MATbaSymbolsCount > 0 || f.CMESymbolsCount > 0 {
		return AccountProFutures
	}
	if r.HasPasswordInConfig || f.Username != "" {
		return AccountProFutures
	}
	return AccountUnknown
}

// classifyProduct picks the dominant product class.
func classifyProduct(f CQGFields) ProductClass {
	matba := f.MATbaSymbolsCount > 0
	cme := f.CMESymbolsCount > 0
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
