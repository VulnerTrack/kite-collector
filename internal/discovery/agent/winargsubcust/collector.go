package winargsubcust

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const MaxWalkDepth = 6

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

func (c *fileCollector) Name() string { return "winargsubcust" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SUBCUST_DIR")); p != "" {
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
			for _, rel := range UserSubCustDirs() {
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
		FilePath:        path,
		FileSize:        fi.Size(),
		FileMode:        int(fi.Mode().Perm()),
		FileOwnerUID:    ownerUID(fi),
		UserProfile:     user,
		ArtifactKind:    ArtifactKindFromName(base),
		SubCustBank:     SubCustBankFromName(base),
		SubCustRole:     RoleUnknown,
		ReportingPeriod: PeriodFromFilename(base),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody && fi.Size() <= MaxFileBytes {
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
	fields := ParseSubCust(body)
	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.SubCustBank != "" && fields.SubCustBank != BankUnknown {
		row.SubCustBank = fields.SubCustBank
	}
	if fields.GlobalCustodian != "" && fields.GlobalCustodian != GCUnknown {
		row.GlobalCustodian = fields.GlobalCustodian
	}
	if fields.DGTTreatyCountry != "" && fields.DGTTreatyCountry != DGTUnknown {
		row.DGTTreatyCountry = fields.DGTTreatyCountry
	}
	if fields.SubCustCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.SubCustCuitRaw); p != "" {
			row.SubCustCuitPrefix = p
			row.SubCustCuitSuffix4 = s
		}
	}
	if fields.ForeignTINCountry != "" && fields.ForeignTINRaw != "" {
		row.ForeignTINCountry = fields.ForeignTINCountry
		row.ForeignTINSuffix4 = TINSuffix4(fields.ForeignTINRaw)
	}
	if fields.SWIFTBIC != "" {
		row.SWIFTBICHash = HashSecret(fields.SWIFTBIC)
	}
	if fields.OmnibusAccountRaw != "" {
		row.OmnibusAccountHash = HashSecret(fields.OmnibusAccountRaw)
	}
	if fields.ForeignBOCount > 0 {
		row.ForeignBOCount = fields.ForeignBOCount
	}
	if fields.OmnibusAccountCount > 0 {
		row.OmnibusAccountCount = fields.OmnibusAccountCount
	}
	if fields.OmnibusValueARS > 0 {
		row.OmnibusValueARS = fields.OmnibusValueARS
	}
	if fields.FXClearanceAmountUSD > 0 {
		row.FXClearanceAmountUSD = fields.FXClearanceAmountUSD
	}
	if fields.WithholdingAmountARS > 0 {
		row.WithholdingAmountARS = fields.WithholdingAmountARS
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
