package winargcnvaif

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

// fileCollector walks AIF install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcnvaif" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CNV_AIF_DIR")); p != "" {
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
			for _, rel := range UserAIFDirs() {
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
	kind := ArtifactKindFromName(filepath.Base(path))
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ArtifactKind: kind,
		TipoEmision:  TipoUnknown,
	}
	// Per-kind preset.
	switch kind {
	case KindDDJJBeneficiarios:
		// DDJJ tipo 3 by definition carries beneficial-owner data;
		// presence is rolled up at AnnotateSecurity below via the
		// per-row beneficial_owner_count.
		row.BeneficialOwnerCount = 1
	case KindDesignacionDirect:
		row.HasDirectorioChange = true
	case KindProspectoEmision, KindSuplementoProspecto:
		row.HasCapitalChange = true
	case KindActaAsamblea, KindConvocatoriaAsamblea,
		KindDDJJAutoridades, KindDDJJAccionistas,
		KindContratoFideicomiso, KindReglamentoGestion,
		KindAdenda, KindOther, KindUnknown:
		// no-op
	}
	if prefix, suffix := EmisorCuitFingerprint(filepath.Base(path)); prefix != "" {
		row.EmisorCuitPrefix = prefix
		row.EmisorCuitSuffix4 = suffix
	}
	if t := TickerFromText(filepath.Base(path)); t != "" {
		row.EmisorTicker = t
	}
	if id := DocumentoAIFIDFromText(filepath.Base(path)); id != "" {
		row.DocumentoAIFID = id
	}

	ext := strings.ToLower(filepath.Ext(path))
	parseable := ext == ".xml" || ext == ".txt"
	if parseable && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseAIFArtifact(body); ok {
				if row.EmisorCuitPrefix == "" && fields.EmisorCuitRaw != "" {
					row.EmisorCuitPrefix, row.EmisorCuitSuffix4 = EmisorCuitFingerprint(fields.EmisorCuitRaw)
				}
				if row.EmisorTicker == "" && fields.Ticker != "" {
					row.EmisorTicker = fields.Ticker
				}
				if row.DocumentoAIFID == "" && fields.DocumentoAIFID != "" {
					row.DocumentoAIFID = fields.DocumentoAIFID
				}
				if row.TipoEmision == TipoUnknown && fields.TipoEmisionText != "" {
					row.TipoEmision = TipoEmisionFromText(fields.TipoEmisionText)
				}
				if row.FechaAprobacion == "" && fields.FechaAprobacion != "" {
					row.FechaAprobacion = fields.FechaAprobacion
				}
				if row.VigenciaDesde == "" && fields.VigenciaDesde != "" {
					row.VigenciaDesde = fields.VigenciaDesde
				}
				if row.VigenciaHasta == "" && fields.VigenciaHasta != "" {
					row.VigenciaHasta = fields.VigenciaHasta
				}
				if row.MontoEmisionARSCents == 0 {
					row.MontoEmisionARSCents = DecimalToCents(fields.MontoARSText)
				}
				if row.MontoEmisionUSDCents == 0 {
					row.MontoEmisionUSDCents = DecimalToCents(fields.MontoUSDText)
				}
				if fields.BeneficialOwnerCount > row.BeneficialOwnerCount {
					row.BeneficialOwnerCount = fields.BeneficialOwnerCount
				}
				if fields.HasDirectorioChange {
					row.HasDirectorioChange = true
				}
				if fields.HasCapitalChange {
					row.HasCapitalChange = true
				}
			}
		}
	} else {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
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
