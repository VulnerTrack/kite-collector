package winanses

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

// fileCollector walks ANSES install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winanses" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("ANSES_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("KYC_HOME")); p != "" {
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
			if isSystemPseudoProfile(name) {
				continue
			}
			for _, rel := range UserAnsesDirs() {
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
		if !isCandidateExt(e.Name()) {
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
		FilePath:         path,
		FileSize:         fi.Size(),
		FileMode:         int(fi.Mode().Perm()),
		FileOwnerUID:     ownerUID(fi),
		UserProfile:      user,
		ConsultationKind: ConsultationKindFromName(filepath.Base(path)),
		FechaAcceso:      fi.ModTime().UTC().Format(time.RFC3339),
	}
	if prefix, suffix := CuilFingerprint(filepath.Base(path)); prefix != "" {
		row.TargetCuilPrefix = prefix
		row.TargetCuilSuffix4 = suffix
	}

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			// Body-side classification can promote the kind.
			if ContainsAnyToken(body, JubilacionTokens()) {
				row.HasJubilacionStatus = true
				if row.ConsultationKind == KindCUILIndividual ||
					row.ConsultationKind == KindOther ||
					row.ConsultationKind == KindUnknown {
					row.ConsultationKind = KindJubilacion
				}
			}
			if ContainsAnyToken(body, AUHTokens()) {
				row.HasAUHStatus = true
				if row.ConsultationKind == KindCUILIndividual ||
					row.ConsultationKind == KindOther ||
					row.ConsultationKind == KindUnknown {
					row.ConsultationKind = KindAUHStatus
				}
			}
			if ContainsAnyToken(body, GrupoFamiliarTokens()) {
				row.HasGrupoFamiliar = true
				row.DependentCount = CountDependents(body)
				if row.ConsultationKind == KindCUILIndividual ||
					row.ConsultationKind == KindOther ||
					row.ConsultationKind == KindUnknown {
					row.ConsultationKind = KindGrupoFamiliar
				}
			}
			if ContainsAnyToken(body, AportesTokens()) {
				row.HasAportesHistorial = true
			}
			if ContainsMinorDate(body) {
				row.HasMinorDependent = true
			}
			// Audit-log + batch count.
			if row.ConsultationKind == KindAuditLog ||
				row.ConsultationKind == KindCUILBatch {
				row.ConsultationCount = CountLinesAsLog(body)
			}
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".jsonl", ".txt", ".csv", ".tsv", ".log":
		return true
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
