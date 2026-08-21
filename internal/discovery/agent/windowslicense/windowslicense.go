// Package windowslicense analyses the Windows OS licence and
// activation posture via a PowerShell shim (no go-ole / COM
// dependency), extending the MID-Server-aligned Windows track that
// windowsinfo opened — one row per machine answering "is this host's
// operating system properly licensed?", joinable against
// host_windows_info via machine_id.
//
// The collector shells out to PowerShell with a single inline script
// that runs two CIM queries (SoftwareLicensingProduct filtered to the
// Windows application GUID with a populated partial product key, and
// the SoftwareLicensingService singleton) and emits one compact JSON
// object — the same slmgr.vbs surface, without the VBScript host.
//
// Captured per machine: activation status (licensed / grace /
// notification / non-genuine / unlicensed), licence channel (retail,
// OEM, volume KMS client, volume MAK, evaluation), KMS server wiring
// (configured + auto-discovered), rearm budget, evaluation deadline,
// and whether the firmware carries an OA3 embedded product key.
//
// Product keys are NEVER persisted verbatim (same contract as
// winsoftwarelicences). The firmware OA3x key is SHA-256-hashed
// INSIDE the PowerShell script, so the raw key never crosses the
// process boundary into Go — it cannot leak via error paths that
// embed combined output. Only the 5-character PartialProductKey that
// slmgr /dli already shows to any local user is kept in clear.
//
// Headline finding shapes (ISO/IEC 27001:2022 A.5.32 — the OS is the
// first licence an inventory must prove):
//
//   - `is_unlicensed=1` / `is_notification_mode=1` — host runs
//     without a valid licence.
//   - `is_non_genuine=1` — activation flagged non-genuine.
//   - `is_grace_expiring_soon=1` — grace runs out within 7 days.
//   - `is_evaluation_expired=1` — evaluation build past deadline.
//   - `is_license_compliance_risk=1` — any of the above.
//
// Read-only by intent. (Project guideline 4.2.)
package windowslicense

import (
	"context"
	"time"
)

// Source identifies which probe produced the row. Pinned to the
// host_windows_license.source CHECK enum.
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourceUnknown       Source = "unknown"
)

// Status is the decoded SoftwareLicensingProduct.LicenseStatus.
// Pinned to the host_windows_license.license_status CHECK enum.
type Status string

const (
	StatusUnlicensed      Status = "unlicensed"        // 0
	StatusLicensed        Status = "licensed"          // 1
	StatusOOBGrace        Status = "oob-grace"         // 2 initial grace
	StatusOOTGrace        Status = "oot-grace"         // 3 out-of-tolerance
	StatusNonGenuineGrace Status = "non-genuine-grace" // 4
	StatusNotification    Status = "notification"      // 5
	StatusExtendedGrace   Status = "extended-grace"    // 6
	StatusUnknown         Status = "unknown"
)

// Channel is the licence acquisition channel. Pinned to the
// host_windows_license.channel CHECK enum.
type Channel string

const (
	ChannelRetail       Channel = "retail"
	ChannelOEM          Channel = "oem"
	ChannelVolumeKMS    Channel = "volume-kms-client"
	ChannelVolumeMAK    Channel = "volume-mak"
	ChannelEvaluation   Channel = "evaluation"
	ChannelUnknownValue Channel = "unknown"
)

// GraceExpiryWindow defines the is_grace_expiring_soon cutoff.
const GraceExpiryWindow = 7 * 24 * time.Hour

// CountUnknown marks a rearm counter the probe could not read
// (property absent on old builds, or query denied). Distinct from 0,
// which means "budget exhausted".
const CountUnknown int64 = -1

// Info is the cross-OS record. On non-Windows platforms the collector
// returns the zero value; the audit pipeline treats an empty
// ProductName with LicenseStatusCode 0 and Source "" as "no probe
// data" (see HasData) and skips Windows-specific joins.
//
// Mirrors host_windows_license's column shape exactly.
type Info struct {
	ProductName            string  `json:"product_name,omitempty"`
	Description            string  `json:"description,omitempty"`
	LicenseStatus          Status  `json:"license_status"`
	LicenseStatusReason    string  `json:"license_status_reason,omitempty"`
	PartialProductKey      string  `json:"partial_product_key,omitempty"`
	LicenseFamily          string  `json:"license_family,omitempty"`
	ProductKeyChannel      string  `json:"product_key_channel,omitempty"`
	Channel                Channel `json:"channel"`
	EvaluationEndDate      string  `json:"evaluation_end_date,omitempty"`
	KMSConfiguredServer    string  `json:"kms_configured_server,omitempty"`
	KMSDiscoveredServer    string  `json:"kms_discovered_server,omitempty"`
	FirmwareKeyHash        string  `json:"firmware_key_hash,omitempty"`
	FirmwareKeyDescription string  `json:"firmware_key_description,omitempty"`
	Source                 Source  `json:"source"`

	GracePeriodRemainingMinutes int64 `json:"grace_period_remaining_minutes"`
	RemainingSKURearmCount      int64 `json:"remaining_sku_rearm_count"`
	RemainingWindowsRearmCount  int64 `json:"remaining_windows_rearm_count"`
	KMSConfiguredPort           int64 `json:"kms_configured_port,omitempty"`
	KMSDiscoveredPort           int64 `json:"kms_discovered_port,omitempty"`

	LicenseStatusCode int `json:"license_status_code"`

	IsKMSHost              bool `json:"is_kms_host"`
	HasFirmwareEmbeddedKey bool `json:"has_firmware_embedded_key"`

	// Derived posture booleans — set by Annotate.
	IsActivated             bool `json:"is_activated"`
	IsGracePeriod           bool `json:"is_grace_period"`
	IsNonGenuine            bool `json:"is_non_genuine"`
	IsNotificationMode      bool `json:"is_notification_mode"`
	IsUnlicensed            bool `json:"is_unlicensed"`
	IsEvaluation            bool `json:"is_evaluation"`
	IsEvaluationExpired     bool `json:"is_evaluation_expired"`
	IsKMSClient             bool `json:"is_kms_client"`
	IsGraceExpiringSoon     bool `json:"is_grace_expiring_soon"`
	IsRearmExhausted        bool `json:"is_rearm_exhausted"`
	IsLicenseComplianceRisk bool `json:"is_license_compliance_risk"`
}

// HasData reports whether the probe produced a usable row. The
// non-Windows stub and a fully-denied WMI surface both yield the zero
// value, which the audit pipeline must skip rather than persist.
func (i Info) HasData() bool {
	return i.Source != "" && (i.ProductName != "" || i.LicenseStatus != StatusUnknown)
}

// Collector is the read-only contract every per-OS implementation
// satisfies. The Windows implementation lives in collector_windows.go;
// non-Windows platforms use the stub in collector_other.go.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Info, error)
}

// StatusFromCode decodes SoftwareLicensingProduct.LicenseStatus.
func StatusFromCode(code int) Status {
	switch code {
	case 0:
		return StatusUnlicensed
	case 1:
		return StatusLicensed
	case 2:
		return StatusOOBGrace
	case 3:
		return StatusOOTGrace
	case 4:
		return StatusNonGenuineGrace
	case 5:
		return StatusNotification
	case 6:
		return StatusExtendedGrace
	}
	return StatusUnknown
}

// Annotate sets the derived posture booleans from the raw fields.
func Annotate(i *Info) {
	AnnotateWithClock(i, time.Now)
}

// AnnotateWithClock is the time-injectable variant.
func AnnotateWithClock(i *Info, now func() time.Time) {
	switch i.LicenseStatus {
	case StatusLicensed:
		i.IsActivated = true
	case StatusOOBGrace, StatusOOTGrace, StatusExtendedGrace:
		i.IsGracePeriod = true
	case StatusNonGenuineGrace:
		i.IsNonGenuine = true
	case StatusNotification:
		i.IsNotificationMode = true
	case StatusUnlicensed:
		i.IsUnlicensed = true
	case StatusUnknown:
		// No probe data — leave every posture boolean unset.
	}
	if i.Channel == ChannelEvaluation || i.EvaluationEndDate != "" {
		i.IsEvaluation = true
	}
	if i.EvaluationEndDate != "" {
		if t, err := time.Parse(time.RFC3339, i.EvaluationEndDate); err == nil {
			if t.Before(now()) {
				i.IsEvaluationExpired = true
			}
		}
	}
	if i.Channel == ChannelVolumeKMS ||
		i.KMSConfiguredServer != "" || i.KMSDiscoveredServer != "" {
		i.IsKMSClient = true
	}
	if i.IsGracePeriod && i.GracePeriodRemainingMinutes > 0 &&
		time.Duration(i.GracePeriodRemainingMinutes)*time.Minute < GraceExpiryWindow {
		i.IsGraceExpiringSoon = true
	}
	if i.RemainingWindowsRearmCount == 0 && i.LicenseStatus != StatusUnknown {
		i.IsRearmExhausted = true
	}
	if i.IsUnlicensed || i.IsNonGenuine || i.IsNotificationMode ||
		i.IsEvaluationExpired {
		i.IsLicenseComplianceRisk = true
	}
}
