package winargcrypto

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

// fileCollector walks crypto install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcrypto" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CRYPTO_DIR")); p != "" {
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
			for _, rel := range UserCryptoDirs() {
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
		Exchange:     ExchangeFromPath(path),
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	row.PSAVClass = PSAVClassFromExchange(row.Exchange)
	if row.Exchange == ExchangeUnknown && row.ArtifactKind == KindWalletSeed {
		row.PSAVClass = PSAVWalletNonCustodial
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".xlsx"
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
	// Exchange from body — overrides path-based UNKNOWN when a
	// hostname / token is in the body.
	if row.Exchange == ExchangeUnknown {
		row.Exchange = ExchangeFromPath(string(body))
		if row.Exchange != ExchangeUnknown {
			row.PSAVClass = PSAVClassFromExchange(row.Exchange)
		}
	}
	if row.Exchange == ExchangeUnknown {
		row.Exchange = ExchangeOther
	}
	if row.PSAVClass == PSAVUnknown && row.ArtifactKind == KindWalletSeed {
		row.PSAVClass = PSAVWalletNonCustodial
	} else if row.PSAVClass == PSAVUnknown {
		row.PSAVClass = PSAVOther
	}

	var fields CryptoFields
	switch row.ArtifactKind {
	case KindAPIKey, KindCCXTCache:
		fields = ParseCryptoCredentials(body)
	case KindOTCP2PLog:
		fields = ParseCryptoOTCLog(body)
	case KindStablecoinLog:
		fields = ParseCryptoStablecoinLog(body)
	case KindAccountExport, KindTaxReport:
		fields = ParseCryptoAccountExport(body)
	case KindWalletSeed:
		fields = ParseCryptoWalletSeed(body)
	case KindStrategyScript:
		fields = ParseCryptoStrategy(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasAPIKey {
		row.HasAPIKey = true
		if fields.APIKey != "" {
			row.APIKeyHash = HashSecret(fields.APIKey)
		}
	}
	if fields.HasAPISecret {
		row.HasAPISecret = true
	}
	if fields.HasWalletSeedMarker {
		row.HasWalletSeedMarker = true
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
	row.TradeCount = fields.TradeCount
	row.OTCP2PCount = fields.OTCP2PCount
	row.StablecoinVolumeARSCents = fields.StablecoinCents
	if fields.MaxTradeCents > 0 {
		row.MaxTradeARSCents = fields.MaxTradeCents
	}
	row.DistinctPairCount = fields.DistinctPairCount

	// AFIP-unreported flag: large volume + no AFIP marker.
	if !fields.HasAfipMarker &&
		(row.StablecoinVolumeARSCents >= AfipUnreportedThresholdCents ||
			row.MaxTradeARSCents >= AfipUnreportedThresholdCents) {
		row.HasAfipUnreported = true
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
