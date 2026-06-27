package winargmaeclear

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

// fileCollector walks MAEclear install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargmaeclear" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("MAECLEAR_DIR")); p != "" {
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
			for _, rel := range UserMAEclearDirs() {
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
	var fields MAEClearFields
	switch row.ArtifactKind {
	case KindCredentials, KindConfig:
		fields = ParseMAEclearCredentials(body)
	case KindSettlementBook:
		fields = ParseMAEclearSettlementBook(body)
	case KindAffirmationLog:
		fields = ParseMAEclearAffirmationLog(body)
	case KindRepoBook:
		fields = ParseMAEclearRepoBook(body)
	case KindLeliqLog:
		fields = ParseMAEclearLeliqLog(body)
	case KindDropCopy:
		fields = ParseMAEclearDropCopy(body)
	case KindSessionLog:
		fields = ParseMAEclearSessionLog(body)
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
		row.SettlementFirstSeen = fields.SessionFirstSeen
	}
	if fields.SessionLastSeen != "" {
		row.SettlementLastSeen = fields.SessionLastSeen
	}
	if fields.SettlementCount > 0 {
		row.SettlementCount = fields.SettlementCount
	}
	if fields.SettlementFailCount > 0 {
		row.SettlementFailCount = fields.SettlementFailCount
	}
	if fields.AffirmationCount > 0 {
		row.AffirmationCount = fields.AffirmationCount
	}
	if fields.RepoCount > 0 {
		row.RepoCount = fields.RepoCount
	}
	if fields.RepoMaxTenorDays > 0 {
		row.RepoMaxTenorDays = fields.RepoMaxTenorDays
	}
	if fields.LeliqSettlementCount > 0 {
		row.LeliqSettlementCount = fields.LeliqSettlementCount
	}
	if fields.SovereignOTCCount > 0 {
		row.SovereignOTCCount = fields.SovereignOTCCount
	}
	if fields.FXForwardCount > 0 {
		row.FXForwardCount = fields.FXForwardCount
	}
	if fields.TotalVolumeCents > 0 {
		row.TotalVolumeARSCents = fields.TotalVolumeCents
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
	row.AccountClass = classifyAccount(fields)
}

// classifyAccount picks an account-class from parsed fields.
func classifyAccount(f MAEClearFields) AccountClass {
	if f.LeliqSettlementCount > 0 {
		return AccountBank
	}
	if f.HasFIXDropCopy {
		return AccountBank
	}
	if f.RepoCount > 0 || f.AffirmationCount > 0 {
		return AccountALYC
	}
	if f.SovereignOTCCount > 0 {
		return AccountSociedadGerente
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
