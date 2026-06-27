package winargmaeonlinefx

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

// fileCollector walks MAE OnlineFX install roots + user dirs.
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

func (c *fileCollector) Name() string { return "winargmaeonlinefx" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("MAE_ONLINEFX_DIR")); p != "" {
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
			for _, rel := range UserMAEOnlineFXDirs() {
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
		ParticipantClass: ParticipantUnknown,
		PeriodYYYYMM:     PeriodFromFilename(base),
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
	var fields MAEFXFields
	switch row.ArtifactKind {
	case KindCredentials, KindConfig:
		fields = ParseMAEFXCredentials(body)
	case KindQuotesCache:
		fields = ParseMAEFXQuotesCache(body)
	case KindTradeBlotter:
		fields = ParseMAEFXTradeBlotter(body)
	case KindForwardBook:
		fields = ParseMAEFXForwardBook(body)
	case KindNDFBook:
		fields = ParseMAEFXNDFBook(body)
	case KindUSDTBook:
		fields = ParseMAEFXUSDTBook(body)
	case KindFIXDropCopy:
		fields = ParseMAEFXFIXDropCopy(body)
	case KindSessionLog:
		fields = ParseMAEFXSessionLog(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.ParticipantID != "" {
		row.ParticipantID = fields.ParticipantID
	}
	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasFIXDropCopy {
		row.HasFIXDropCopy = true
	}
	if fields.FIXSenderCompID != "" {
		row.FIXSessionSender = fields.FIXSenderCompID
	}
	if fields.FIXTargetCompID != "" {
		row.FIXSessionTarget = fields.FIXTargetCompID
	}
	if fields.SessionFirstSeen != "" {
		row.SessionFirstSeen = fields.SessionFirstSeen
	}
	if fields.SessionLastSeen != "" {
		row.SessionLastSeen = fields.SessionLastSeen
	}
	if fields.TradeCount > 0 {
		row.TradeCount = fields.TradeCount
	}
	if fields.SpotCount > 0 {
		row.SpotTradeCount = fields.SpotCount
	}
	if fields.ForwardCount > 0 {
		row.ForwardTradeCount = fields.ForwardCount
	}
	if fields.NDFCount > 0 {
		row.NDFTradeCount = fields.NDFCount
	}
	if fields.USDTCount > 0 {
		row.USDTTradeCount = fields.USDTCount
	}
	if fields.BRLCount > 0 {
		row.BRLTradeCount = fields.BRLCount
	}
	if fields.EURCount > 0 {
		row.EURTradeCount = fields.EURCount
	}
	if fields.TotalVolumeUSDCents > 0 {
		row.TotalVolumeUSDCents = fields.TotalVolumeUSDCents
	}
	if fields.AboveCapCount > 0 {
		row.AboveCapCount = fields.AboveCapCount
	}
	if fields.DistinctCounterparties > 0 {
		row.DistinctCounterpartyCount = fields.DistinctCounterparties
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	row.ParticipantClass = classifyParticipant(fields, *row)
}

// classifyParticipant picks a participant class from parsed
// fields + artifact kind.
func classifyParticipant(f MAEFXFields, r Row) ParticipantClass {
	if f.HasFIXDropCopy {
		return ParticipantBank
	}
	if f.USDTCount > 0 || r.ArtifactKind == KindUSDTBook {
		return ParticipantCriptoExchange
	}
	if f.ForwardCount > 0 || f.NDFCount > 0 {
		return ParticipantBank
	}
	if f.SpotCount > 0 || f.EURCount > 0 || f.BRLCount > 0 {
		return ParticipantALYC
	}
	return ParticipantUnknown
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
