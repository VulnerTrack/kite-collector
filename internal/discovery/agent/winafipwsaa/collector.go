package winafipwsaa

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultUsersBases is the curated set of per-OS user-profile
// bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// CandidateExtensions is the set of file extensions worth
// inspecting. Walker only opens files whose name matches one
// of these AND lives under an AFIP-flavoured path or carries
// an AFIP token in its basename.
func CandidateExtensions() []string {
	return []string{
		".crt", ".cer", ".pem", ".key",
		".p12", ".pfx",
		".xml", ".cms",
		".ini", ".cfg", ".json", ".yml", ".yaml",
	}
}

// MaxWalkDepth bounds per-user tree depth so we don't recurse
// into the entire profile. AFIP integrations universally place
// keys within 6 levels of the user home.
const MaxWalkDepth = 6

// MaxFileBytes bounds the size we'll read for content
// inspection. Real AFIP artifacts are <64 KiB; the cap
// protects against huge unrelated XMLs.
const MaxFileBytes = 1 << 20 // 1 MiB

// fileCollector walks per-user trees looking for AFIP
// artifacts. Test seam swaps readFile / readDir / statFile /
// getenv / now.
type fileCollector struct {
	now        func() time.Time
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
		now:        time.Now,
	}
}

func (c *fileCollector) Name() string { return "winafipwsaa" }

func (c *fileCollector) Collect(_ context.Context) ([]Artifact, error) {
	out := make([]Artifact, 0, 16)

	// Env-var override (some SDKs honour PYAFIPWS_HOME or
	// AFIPSDK_CERT_PATH for the cert dir).
	for _, k := range []string{"PYAFIPWS_HOME", "AFIPSDK_CERT_PATH", "AFIP_CERT_DIR"} {
		if p := strings.TrimSpace(c.getenv(k)); p != "" {
			c.walk(p, "", &out, 0)
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			c.walk(filepath.Join(base, name), name, &out, 0)
			if len(out) >= MaxArtifacts {
				break
			}
		}
		if len(out) >= MaxArtifacts {
			break
		}
	}

	if len(out) > MaxArtifacts {
		out = out[:MaxArtifacts]
	}
	SortArtifacts(out)
	return out, nil
}

// walk descends `dir`, depth-bounded, considering each
// candidate file for AFIP relevance.
func (c *fileCollector) walk(dir, user string, out *[]Artifact, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxArtifacts {
				return
			}
			continue
		}
		if !isCandidateName(e.Name()) {
			continue
		}
		// AFIP-relevance gate: either path token or basename
		// token must match.
		if !IsAfipPath(full) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxArtifacts {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, out *[]Artifact) {
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	if fi.Size() > MaxFileBytes {
		// Inventory metadata only — skip content inspection.
		a := Artifact{
			FilePath:     path,
			FileSize:     fi.Size(),
			FileMode:     int(fi.Mode().Perm()),
			FileOwnerUID: ownerUID(fi),
			UserProfile:  user,
			ArtifactKind: ClassifyByExtension(path),
			EndpointEnv:  DetectEndpointEnv(path),
		}
		AnnotateSecurity(&a)
		*out = append(*out, a)
		return
	}
	body, err := c.readFile(path)
	if err != nil {
		if !isNotExist(err) {
			return
		}
		return
	}
	hash := HashContents(body)
	a := Artifact{
		FilePath:     path,
		FileHash:     hash,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ArtifactKind: ClassifyByExtension(path),
		EndpointEnv:  DetectEndpointEnv(path),
	}

	// Content-based classifier disambiguates .xml.
	if a.ArtifactKind == ArtifactUnknown && strings.EqualFold(filepath.Ext(path), ".xml") {
		if ta, ok := ParseTicketAcceso(body, c.now()); ok {
			a.ArtifactKind = ArtifactTAXML
			a.TaExpiresAt = ta.ExpiresAt
			a.IsTaTokenPresent = ta.IsTokenPresent
			a.IsTaExpired = ta.IsExpired
			if ta.SourceCuitPfx != "" {
				a.CuitEntityPrefix = ta.SourceCuitPfx
				a.CuitSuffix4 = ta.SourceCuitSfx4
			} else if ta.DestCuitPfx != "" {
				a.CuitEntityPrefix = ta.DestCuitPfx
				a.CuitSuffix4 = ta.DestCuitSfx4
			}
		}
	} else if a.ArtifactKind == ArtifactTAXML || strings.HasSuffix(strings.ToLower(path), ".ta.xml") {
		a.ArtifactKind = ArtifactTAXML
		if ta, ok := ParseTicketAcceso(body, c.now()); ok {
			a.TaExpiresAt = ta.ExpiresAt
			a.IsTaTokenPresent = ta.IsTokenPresent
			a.IsTaExpired = ta.IsExpired
			if ta.SourceCuitPfx != "" {
				a.CuitEntityPrefix = ta.SourceCuitPfx
				a.CuitSuffix4 = ta.SourceCuitSfx4
			} else if ta.DestCuitPfx != "" {
				a.CuitEntityPrefix = ta.DestCuitPfx
				a.CuitSuffix4 = ta.DestCuitSfx4
			}
		}
	}

	switch a.ArtifactKind {
	case ArtifactPrivateKey:
		if k, ok := AnalyzePrivateKey(body); ok {
			a.IsPrivateKeyUnencrypted = k.IsUnencrypted
		}
	case ArtifactCert:
		if cert, ok := AnalyzeCert(body); ok {
			a.SubjectCN = cert.SubjectCN
			if cert.CuitEntityPrefix != "" {
				a.CuitEntityPrefix = cert.CuitEntityPrefix
				a.CuitSuffix4 = cert.CuitSuffix4
			}
		}
	case ArtifactPKCS12, ArtifactTAXML, ArtifactTRACMS, ArtifactWSAAConfig, ArtifactUnknown:
		// no content-derived fields beyond what's set above
	}

	AnnotateSecurity(&a)
	*out = append(*out, a)
}

func isCandidateName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	for _, e := range CandidateExtensions() {
		if ext == e {
			return true
		}
	}
	return false
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

func isNotExist(err error) bool {
	return err != nil && (os.IsNotExist(err) || isFsNotExist(err))
}

func isFsNotExist(err error) bool {
	if err == nil {
		return false
	}
	var e *fs.PathError
	if errors.As(err, &e) {
		return os.IsNotExist(e.Err)
	}
	return false
}
