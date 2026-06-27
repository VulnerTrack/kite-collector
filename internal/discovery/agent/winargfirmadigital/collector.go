package winargfirmadigital

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

// fileCollector walks firma-digital install roots + per-user
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

func (c *fileCollector) Name() string { return "winargfirmadigital" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("FIRMA_DIGITAL_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("ONTI_HOME")); p != "" {
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
			for _, rel := range UserFirmaDirs() {
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
		// Skip files already covered by iter 88 winafipwsaa.
		if IsAfipWsaaPath(full) {
			continue
		}
		// Loose filename gate — accept any cert file under
		// firma-digital tree, or any cert file with a firma
		// token in its name.
		if !IsCandidateName(filepath.Base(full)) {
			// Also accept the file if we're under a firma-digital
			// install root (i.e. the directory is gated).
			if !isUnderFirmaRoot(full) {
				continue
			}
		}
		c.consider(full, user, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func isUnderFirmaRoot(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, tok := range []string{
		"/firmadigital/", "/firma-digital/", "/onti/",
		"/ac-modernizacion/", "/certificados/",
	} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
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
		CertKind:     CertKindFromExt(path),
	}

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			// PEM/DER cert content parse — only for cert extensions.
			ext := strings.ToLower(filepath.Ext(path))
			var (
				fields CertFields
				ok     bool
			)
			switch ext {
			case ".pem", ".crt":
				fields, ok = ParseCertPEM(body)
			case ".cer", ".der":
				fields, ok = ParseCertDER(body)
				if !ok {
					// Fall back to PEM in case extension was wrong.
					fields, ok = ParseCertPEM(body)
				}
			}
			if ok {
				row.SubjectCN = TruncateString(fields.SubjectCN, MaxSubjectCNChars)
				row.IssuerCA = IssuerCAFromText(fields.IssuerDN)
				row.ValidFrom = fields.ValidFrom.UTC().Format(time.RFC3339)
				row.ValidTo = fields.ValidTo.UTC().Format(time.RFC3339)
				if fields.IsCA || fields.IsSelfSigned {
					row.CertKind = KindCACert
				}
				// CUIT from Subject serialNumber, then full DN.
				if sn := SubjectSerialNumberFromDN(fields.SubjectDN); sn != "" {
					row.SubjectCuitPrefix, row.SubjectCuitSuffix4 = CuitFingerprintFromText(sn)
				}
				if row.SubjectCuitPrefix == "" {
					row.SubjectCuitPrefix, row.SubjectCuitSuffix4 = CuitFingerprintFromText(fields.SubjectDN)
				}
			}
		}
	}
	if row.IssuerCA == "" {
		row.IssuerCA = IssuerUnknown
	}

	AnnotateSecurityWithClock(&row, c.now)
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
