// Package winafipdfe audits Argentine AFIP / ARCA Domicilio
// Fiscal Electrónico (DFE) notification files cached on
// compliance / accounting workstations across Windows, Linux,
// and macOS.
//
// Every contribuyente registers a DFE for receiving formal
// tax-authority notifications: intimación de pago,
// requerimiento de documentación, inicio procedimiento de
// determinación de oficio, sanción / multa, ajuste impositivo,
// citación.
//
// **The administrative tax-authority enforcement channel.**
// Complements PJN (iter 96, judicial), UIF ROS (iter 99, AML
// out), BCRA Comm (iter 101, regulatory in).
//
// Headline finding shapes:
//
//   - `is_intimacion_pago=1` — back-tax claim.
//   - `is_audit_initiation=1` — procedimiento de
//     determinación de oficio iniciado.
//   - `is_sancion=1` — penalty.
//   - `is_pending_response=1` — estado=pendiente + deadline
//     upcoming. Compliance-deadline alert.
//   - `is_overdue=1` — estado=vencida; default risk.
//   - `is_high_value=1` — monto > 10 M ARS.
//   - `is_credential_exposure_risk=1` — readable file +
//     tax-authority enforcement PII.
//
// Target CUIT NEVER stored verbatim — only entity-type prefix
// + last 4 digits.
//
// Read-only by intent. (Project guideline 4.2.)
package winafipdfe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighValueARSCents — monto threshold for is_high_value
// (10 M ARS = 1 000 000 000 cents).
const HighValueARSCents int64 = 1_000_000_000

// PendingDeadlineWindow — when estado=pendiente AND fecha
// vencimiento ≤ this window from now, flag is_pending_response.
const PendingDeadlineWindow = 30 * 24 * time.Hour

// NotificationKind pinned to host_afip_dfe.notification_kind.
type NotificationKind string

const (
	NotifIntimacionPago      NotificationKind = "intimacion-pago"
	NotifRequerimientoDoc    NotificationKind = "requerimiento-documentacion"
	NotifProcDeterminacion   NotificationKind = "inicio-procedimiento-doficio"
	NotifSancion             NotificationKind = "sancion"
	NotifMulta               NotificationKind = "multa"
	NotifAjusteImpositivo    NotificationKind = "ajuste-impositivo"
	NotifComunicacionGeneral NotificationKind = "comunicacion-general"
	NotifCitacion            NotificationKind = "citacion"
	NotifOther               NotificationKind = "other"
	NotifUnknown             NotificationKind = "unknown"
)

// Estado pinned to host_afip_dfe.estado.
type Estado string

const (
	EstadoPendiente  Estado = "pendiente"
	EstadoLeida      Estado = "leida"
	EstadoContestada Estado = "contestada"
	EstadoVencida    Estado = "vencida"
	EstadoArchivada  Estado = "archivada"
	EstadoUnknown    Estado = "unknown"
)

// Row mirrors host_afip_dfe' column shape.
type Row struct {
	FechaVencimiento         string           `json:"fecha_vencimiento,omitempty"`
	NumeroNotificacion       string           `json:"numero_notificacion,omitempty"`
	FilePath                 string           `json:"file_path"`
	Impuesto                 string           `json:"impuesto,omitempty"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	NotificationKind         NotificationKind `json:"notification_kind"`
	Estado                   Estado           `json:"estado"`
	TargetCuitPrefix         string           `json:"target_cuit_prefix,omitempty"`
	TargetCuitSuffix4        string           `json:"target_cuit_suffix4,omitempty"`
	FechaNotificacion        string           `json:"fecha_notificacion,omitempty"`
	MontoARSCents            int64            `json:"monto_ars_cents,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	IsRecent                 bool             `json:"is_recent"`
	IsAuditInitiation        bool             `json:"is_audit_initiation"`
	IsSancion                bool             `json:"is_sancion"`
	IsPendingResponse        bool             `json:"is_pending_response"`
	IsOverdue                bool             `json:"is_overdue"`
	IsHighValue              bool             `json:"is_high_value"`
	IsIntimacionPago         bool             `json:"is_intimacion_pago"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated DFE install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\DFE`,
		`C:\AFIP\E-Ventanilla`,
		`C:\AFIP\Notificaciones`,
		`C:\ARCA\DFE`,
		`/opt/afip/dfe`,
		`/srv/afip/dfe`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserDFEDirs is the curated per-user relative path set.
func UserDFEDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "DFE"},
		{"Documents", "AFIP", "E-Ventanilla"},
		{"Documents", "AFIP", "Notificaciones"},
		{"Documents", "ARCA", "DFE"},
		{"Documents", "Compliance", "AFIP"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the DFE catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"dfe_", "dfe-", "_dfe",
		"e-ventanilla", "e_ventanilla", "ventanilla_afip",
		"notif_afip", "notificacion_afip",
		"intimacion_", "intimacion-",
		"requerimiento_afip", "requerimiento-afip",
		"sancion_afip", "multa_afip",
		"ajuste_impositivo", "determinacion_oficio",
		"citacion_afip", "afip_citacion",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// NotificationKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens precede generic ones
// (intimacion before notif, multa before sancion since multa
// is a subtype).
func NotificationKindFromName(name string) NotificationKind {
	if strings.TrimSpace(name) == "" {
		return NotifUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "intimacion") || strings.Contains(n, "intimación"):
		return NotifIntimacionPago
	case strings.Contains(n, "determinacion_oficio") ||
		strings.Contains(n, "determinacion-oficio") ||
		strings.Contains(n, "procedimiento_doficio") ||
		strings.Contains(n, "inicio_proc"):
		return NotifProcDeterminacion
	case strings.Contains(n, "requerimiento"):
		return NotifRequerimientoDoc
	case strings.Contains(n, "multa"):
		return NotifMulta
	case strings.Contains(n, "sancion") || strings.Contains(n, "sanción"):
		return NotifSancion
	case strings.Contains(n, "ajuste_impositivo") || strings.Contains(n, "ajuste-impositivo"):
		return NotifAjusteImpositivo
	case strings.Contains(n, "citacion") || strings.Contains(n, "citación"):
		return NotifCitacion
	case strings.Contains(n, "comunicacion") || strings.Contains(n, "comunicación"):
		return NotifComunicacionGeneral
	case strings.Contains(n, "dfe") || strings.Contains(n, "e-ventanilla") ||
		strings.Contains(n, "e_ventanilla") || strings.Contains(n, "notif_afip"):
		return NotifOther
	}
	return NotifUnknown
}

// EstadoFromText classifies a textual estado.
func EstadoFromText(s string) Estado {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return EstadoUnknown
	case strings.Contains(t, "contestada") || strings.Contains(t, "respondida"):
		return EstadoContestada
	case strings.Contains(t, "leida") || strings.Contains(t, "leída") ||
		strings.Contains(t, "read"):
		return EstadoLeida
	case strings.Contains(t, "pendiente") || strings.Contains(t, "pending"):
		return EstadoPendiente
	case strings.Contains(t, "vencida") || strings.Contains(t, "overdue") ||
		strings.Contains(t, "expired"):
		return EstadoVencida
	case strings.Contains(t, "archivada") || strings.Contains(t, "archived"):
		return EstadoArchivada
	}
	return EstadoUnknown
}

// CuitEntityPrefixes mirrors AFIP collector list.
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

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// numeroRE matches DFE notification numbers (typically 6-12
// digits with leading "N°" / "Nro" / "#" / "Numero").
var numeroRE = regexp.MustCompile(`(?i)(?:n[°ºo]|nro|numero|#)\s*[:#-]?\s*(\d{4,12})`)

// NumeroFromText extracts notification number.
func NumeroFromText(text string) string {
	m := numeroRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// ParseFecha parses a date string in DD/MM/YYYY or YYYY-MM-DD
// formats. Returns zero time on failure.
func ParseFecha(s string) time.Time {
	t := strings.TrimSpace(s)
	if t == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02",
		"02/01/2006",
		"02-01-2006",
		"2006/01/02",
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, t); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields + now-stamp via context.
type ClockFn func() time.Time

// AnnotateSecurityWithClock applies AnnotateSecurity and the
// time-sensitive deadline flags using the provided clock.
func AnnotateSecurityWithClock(r *Row, now ClockFn) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	switch r.NotificationKind {
	case NotifIntimacionPago:
		r.IsIntimacionPago = true
	case NotifProcDeterminacion:
		r.IsAuditInitiation = true
	case NotifSancion, NotifMulta:
		r.IsSancion = true
	case NotifRequerimientoDoc, NotifAjusteImpositivo,
		NotifComunicacionGeneral, NotifCitacion,
		NotifOther, NotifUnknown:
		// no specific rollup
	}
	if r.MontoARSCents > HighValueARSCents {
		r.IsHighValue = true
	}
	if r.Estado == EstadoVencida {
		r.IsOverdue = true
	}
	if r.Estado == EstadoPendiente && r.FechaVencimiento != "" && now != nil {
		due := ParseFecha(r.FechaVencimiento)
		current := now()
		if !due.IsZero() {
			if due.Before(current) {
				r.IsOverdue = true
			} else if due.Sub(current) <= PendingDeadlineWindow {
				r.IsPendingResponse = true
			}
		}
	}
	// Tax-authority enforcement PII + readable.
	if r.NotificationKind != "" && r.NotificationKind != NotifUnknown &&
		(r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// AnnotateSecurity is the no-clock convenience for tests that
// don't care about deadline computation.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].TargetCuitPrefix != rs[j].TargetCuitPrefix {
			return rs[i].TargetCuitPrefix < rs[j].TargetCuitPrefix
		}
		return rs[i].TargetCuitSuffix4 < rs[j].TargetCuitSuffix4
	})
}
