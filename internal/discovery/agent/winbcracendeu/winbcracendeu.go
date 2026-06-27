// Package winbcracendeu audits BCRA "Central de Deudores del
// Sistema Financiero" snapshot files cached on Argentine
// banking / consultoría workstations across Windows, Linux,
// and macOS.
//
// BCRA publishes the monthly aggregate of every CUIT's debt
// position across regulated financial institutions; banks,
// risk departments, and rating consultoras download CSV / TXT
// extracts to feed credit-risk pipelines.
//
// BCRA "Situación" scale (Comunicación A 2729 / Texto Ordenado
// Clasificación de Deudores):
//
//   - 1  Normal / cumplimiento puntual
//   - 2  Con seguimiento especial / riesgo bajo
//   - 3  Con problemas
//   - 4  Alto riesgo de insolvencia
//   - 5  Irrecuperable
//   - 6  Irrecuperable por disposición técnica
//
// Situación >= 4 = the entity is functionally insolvent — the
// headline capital-entity-solvency signal for this collector.
//
// File-based discovery is the deliberate design choice — BCRA
// publishes CSV / TXT extracts with a stable schema, and the
// audit pipeline correlates drift via SHA-256 + period.
//
// Headline finding shapes:
//
//   - `has_high_risk_debtors=1` — at least one row carries
//     situación >= 4 (insolvency-risk debtor on file).
//   - `has_cheques_rechazados=1` — the snapshot references
//     rejected-cheque counters (BCRA RG 5237 / RG 5277).
//   - `is_high_value_file=1` — file > 1 MiB (operative
//     snapshot vs. header stub).
//   - `is_credential_exposure_risk=1` — readable file +
//     sensitive snapshot (consolidated or padrón) =
//     CUIT-level debt-PII exposure under Ley 25.326.
//
// Per-entity extracts get a CUIT fingerprint from filename
// (entity-type prefix + last 4 digits, never the full CUIT).
//
// Read-only by intent — we walk candidate files only, never
// call BCRA. (Project guideline 4.2.)
package winbcracendeu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output.
const MaxRows = 8192

// HighValueFileBytes — files above this size are operative
// snapshots (not header stubs).
const HighValueFileBytes int64 = 1 << 20 // 1 MiB

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 128 << 20 // 128 MiB — large CENDEU snapshots

// SnapshotKind pinned to host_bcra_cendeu.snapshot_kind enum.
type SnapshotKind string

const (
	SnapshotConsolidated SnapshotKind = "consolidated"
	SnapshotPerEntity    SnapshotKind = "per-entity"
	SnapshotPadron       SnapshotKind = "padron"
	SnapshotUnknown      SnapshotKind = "unknown"
)

// Row mirrors host_bcra_cendeu' column shape.
type Row struct {
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	FileHash                 string       `json:"file_hash"`
	TargetCuitSuffix4        string       `json:"target_cuit_suffix4,omitempty"`
	TargetCuitPrefix         string       `json:"target_cuit_prefix,omitempty"`
	FilePath                 string       `json:"file_path"`
	UserProfile              string       `json:"user_profile,omitempty"`
	SnapshotKind             SnapshotKind `json:"snapshot_kind"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	RecordCount              int          `json:"record_count,omitempty"`
	DistinctEntityCount      int          `json:"distinct_entity_count,omitempty"`
	MaxSituacion             int          `json:"max_situacion,omitempty"`
	HasChequesRechazados     bool         `json:"has_cheques_rechazados"`
	HasHighRiskDebtors       bool         `json:"has_high_risk_debtors"`
	IsHighValueFile          bool         `json:"is_high_value_file"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated set of BCRA cache roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\BCRA`,
		`C:\BCRA\CENDEU`,
		`C:\Program Files\BCRA`,
		`C:\Program Files (x86)\BCRA`,
		`/opt/bcra`,
		`/srv/bcra`,
	}
}

// CuitEntityPrefixes mirrors the AFIP collector list.
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports prefix membership.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUITs (hyphen-optional) in filenames.
var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

// CuitFingerprintFromName scans a filename for an embedded
// CUIT, returning (prefix, suffix4).
func CuitFingerprintFromName(name string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(name)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	mid := m[2]
	check := m[3]
	suffix4 = mid[len(mid)-3:] + check
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// periodRE matches YYYYMM embedded in filenames.
var periodRE = regexp.MustCompile(`(20\d{2})[-_]?(0[1-9]|1[0-2])`)

// PeriodFromName extracts a YYYYMM period from filename.
func PeriodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// SnapshotKindFromName classifies a filename heuristically.
// `cendeu_<CUIT>.csv` → per-entity; `cendeu_YYYYMM.csv` →
// consolidated; `padron_deudores_YYYYMM.zip` → padron.
func SnapshotKindFromName(name string) SnapshotKind {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case n == "":
		return SnapshotUnknown
	case strings.Contains(n, "padron_deudores") || strings.Contains(n, "padron-deudores"):
		return SnapshotPadron
	case strings.Contains(n, "cendeu") || strings.Contains(n, "central_deudores") ||
		strings.Contains(n, "central-deudores"):
		if prefix, _ := CuitFingerprintFromName(n); prefix != "" {
			return SnapshotPerEntity
		}
		return SnapshotConsolidated
	case strings.Contains(n, "deudor"):
		return SnapshotConsolidated
	}
	return SnapshotUnknown
}

// IsCandidateName reports whether a filename plausibly belongs
// to BCRA's CENDEU export catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"cendeu", "central_deudores", "central-deudores",
		"padron_deudores", "padron-deudores", "deudores-sf",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// SituacionRE matches `situacion=N` / `sit=N` / column N where
// 1 <= N <= 6. Used by the parser to extract per-row debtor
// classification across CSV / fixed-width layouts.
//
// Currently the parser uses a simpler heuristic that scans each
// line for a 1-digit standalone token in {1..6} preceded by a
// CUIT-shaped run; downstream pipelines re-derive precise
// situación from the raw file.
var SituacionRE = regexp.MustCompile(`(?i)\bsituac?(?:ion)?\s*[=:]\s*([1-6])\b|\bsit\s*[=:]\s*([1-6])\b`)

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.FileSize > HighValueFileBytes {
		r.IsHighValueFile = true
	}
	if r.MaxSituacion >= 4 {
		r.HasHighRiskDebtors = true
	}
	sensitive := r.SnapshotKind == SnapshotConsolidated ||
		r.SnapshotKind == SnapshotPadron ||
		r.SnapshotKind == SnapshotPerEntity
	if sensitive && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering by file path then
// period.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].PeriodYYYYMM != rs[j].PeriodYYYYMM {
			return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
		}
		return rs[i].TargetCuitSuffix4 < rs[j].TargetCuitSuffix4
	})
}
