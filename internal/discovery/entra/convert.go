package entra

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Asset Tag JSON keys for the Entra discovery source. Mirrors the
// contract.AttrAD* convention used by the LDAP source — once the central
// telemetry contract grows an Entra section these keys can be promoted there.
const (
	tagTenantID            = "entra.tenant_id"
	tagObjectID            = "entra.object_id"
	tagDeviceID            = "entra.device_id"
	tagTrustType           = "entra.trust_type"
	tagIsCompliant         = "entra.is_compliant"
	tagIsManaged           = "entra.is_managed"
	tagApproxLastSignIn    = "entra.approximate_last_sign_in"
	tagRegistrationDate    = "entra.registration_datetime"
	tagOperatingSystemRaw  = "entra.operating_system_raw"
	tagOSVersionRaw        = "entra.operating_system_version_raw"
	tagDeviceDisplayNameKB = "entra.display_name"
)

// deviceTags assembles the Tags-JSON payload attached to an EntraDevice
// asset. nil-typed fields (compliance, managed) are omitted so downstream
// consumers can distinguish "unknown" from "explicitly false".
func deviceTags(d entraDevice, tenantID string) map[string]any {
	tags := map[string]any{
		tagTenantID:            tenantID,
		tagObjectID:            d.ID,
		tagDeviceID:            d.DeviceID,
		tagTrustType:           normalizeTrustType(d.TrustType),
		tagDeviceDisplayNameKB: d.DisplayName,
	}
	if d.OperatingSystem != "" {
		tags[tagOperatingSystemRaw] = d.OperatingSystem
	}
	if d.OperatingSystemVersion != "" {
		tags[tagOSVersionRaw] = d.OperatingSystemVersion
	}
	if d.IsCompliant != nil {
		tags[tagIsCompliant] = *d.IsCompliant
	}
	if d.IsManaged != nil {
		tags[tagIsManaged] = *d.IsManaged
	}
	if d.ApproximateLastSignInDateTime != "" {
		tags[tagApproxLastSignIn] = d.ApproximateLastSignInDateTime
	}
	if d.RegistrationDateTime != "" {
		tags[tagRegistrationDate] = d.RegistrationDateTime
	}
	return tags
}

// classifyEntraDevice maps the Entra `operatingSystem` field to the kite
// asset taxonomy. Servers, workstations, and mobile clients are all visible
// in /v1.0/devices; we group everything non-server under workstation since
// the kite taxonomy has no dedicated mobile bucket.
func classifyEntraDevice(os string) model.AssetType {
	lower := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.Contains(lower, "windows server"), strings.Contains(lower, "linux server"):
		return model.AssetTypeServer
	case strings.Contains(lower, "server"):
		return model.AssetTypeServer
	case lower == "":
		return model.AssetTypeWorkstation
	default:
		return model.AssetTypeWorkstation
	}
}

// normalizeOS converts the Entra `operatingSystem` label to the canonical
// lowercase OS family used elsewhere in the codebase (windows / darwin /
// linux). Unknown values are returned lowercased verbatim so downstream
// consumers can still match them.
func normalizeOS(os string) string {
	lower := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "macos"),
		strings.Contains(lower, "ios"),
		strings.Contains(lower, "ipados"):
		return "darwin"
	case strings.Contains(lower, "android"),
		strings.Contains(lower, "linux"):
		return "linux"
	default:
		return lower
	}
}

// managedStateFromEntraDevice derives the kite ManagedState from the Entra
// `isManaged` boolean. Devices not enrolled in Intune surface as nil
// `isManaged`, which we treat as Unknown rather than collapsing to
// Unmanaged. The auditor uses the same source field for the ENTRA-005
// finding, so the finding still fires for `is_compliant=false` even when
// `is_managed` is nil.
func managedStateFromEntraDevice(d entraDevice) model.ManagedState {
	if d.IsManaged == nil {
		return model.ManagedUnknown
	}
	if *d.IsManaged {
		return model.ManagedManaged
	}
	return model.ManagedUnmanaged
}

// normalizeTrustType maps the raw trustType returned by Graph onto the
// closed CHECK-constraint set declared in the SQLite migration
// (`AzureAD`, `ServerAD`, `Workplace`). Unknown values fall back to
// `AzureAD` since cloud-joined is the dominant case for Entra-only tenants.
func normalizeTrustType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "serverad", "hybridazureadjoined", "hybrid azure ad joined":
		return "ServerAD"
	case "workplace":
		return "Workplace"
	case "azuread", "":
		return "AzureAD"
	default:
		return "AzureAD"
	}
}
