package winargbloomberg

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

// fileCollector walks Bloomberg install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbloomberg" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BLOOMBERG_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("BLP_DIR")); p != "" {
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
			for _, rel := range UserBloombergDirs() {
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
		SubscriptionTier: TierUnknown,
		ProductClass:     ProductUnknown,
		PeriodYYYYMM:     PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" ||
		ext == ".dmg" || ext == ".cert" || ext == ".crt"
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
	var fields BloombergFields
	switch row.ArtifactKind {
	case KindConfig, KindCredentials:
		fields = ParseBloombergConfig(body)
	case KindLicense:
		fields = ParseBloombergLicense(body)
	case KindSessionLog:
		fields = ParseBloombergSessionLog(body)
	case KindBPipeConfig:
		fields = ParseBloombergBPipeConfig(body)
	case KindAIMConfig:
		fields = ParseBloombergAIMConfig(body)
	case KindBLPAPIScript:
		fields = ParseBloombergBLPAPIScript(body)
	case KindExcelAddin:
		fields = ParseBloombergExcelAddin(body)
	case KindVaultCache:
		fields = ParseBloombergVaultCache(body)
	case KindAnywhereCert:
		fields = ParseBloombergAnywhereCert(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.SessionToken != "" {
		row.HasSessionToken = true
		row.BBGSessionHash = HashSecret(fields.SessionToken)
	}
	if fields.LicenseID != "" {
		row.BBGLicenseIDHash = HashSecret(fields.LicenseID)
	}
	if fields.Username != "" {
		row.UsernameHash = HashSecret(fields.Username)
	}
	if fields.DistinctUsers > 0 {
		row.DistinctUserCount = fields.DistinctUsers
	}
	if fields.DistinctTickers > 0 {
		row.DistinctTickerCount = fields.DistinctTickers
	}
	if fields.DistinctARTickers > 0 {
		row.DistinctARTickerCount = fields.DistinctARTickers
	}
	if fields.HasBLPAPIImport {
		row.HasBLPAPIScript = true
	}
	if fields.HasExcelBLPFormula {
		row.HasExcelBLPAddin = true
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	row.SubscriptionTier = classifySubscription(*row)
	row.ProductClass = classifyProduct(*row)
}

// classifySubscription picks the Bloomberg subscription tier
// based on artifact kind + row signals.
func classifySubscription(r Row) SubscriptionTier {
	switch r.ArtifactKind {
	case KindBPipeConfig:
		return TierBPipe
	case KindAIMConfig:
		return TierAIM
	case KindAnywhereCert:
		return TierAnywhere
	case KindConfig, KindLicense, KindSessionLog, KindCredentials:
		return TierTerminal
	case KindVaultCache, KindBLPAPIScript, KindExcelAddin,
		KindInstaller, KindOther, KindUnknown:
		// fall through to signal-based detection below
	}
	if r.HasBPipeManagedFeed {
		return TierBPipe
	}
	if r.HasAIMFCIManager {
		return TierAIM
	}
	if r.HasAnywhereMobile {
		return TierAnywhere
	}
	return TierUnknown
}

// classifyProduct picks the product class.
func classifyProduct(r Row) ProductClass {
	switch r.ArtifactKind {
	case KindAIMConfig:
		return ProductFCIAIM
	case KindBLPAPIScript, KindExcelAddin, KindVaultCache, KindBPipeConfig:
		return ProductMarketData
	case KindSessionLog:
		return ProductExecutionMgmt
	case KindConfig, KindLicense, KindCredentials, KindAnywhereCert,
		KindInstaller, KindOther, KindUnknown:
		return ProductUnknown
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
