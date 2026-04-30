package driver

import (
	"strings"
	"time"
)

// Sysmon Event ID 6 ("Driver loaded") body keys, kept verbatim from the
// Sysmon schema. SIEM rules written against these keys translate 1:1 to
// OTLP log record attributes when the event is forwarded over our push
// path. Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
const (
	SysmonEventID = 6

	SysmonAttrUTCTime         = "UtcTime"
	SysmonAttrImageLoaded     = "ImageLoaded"
	SysmonAttrFileVersion     = "FileVersion"
	SysmonAttrDescription     = "Description"
	SysmonAttrProduct         = "Product"
	SysmonAttrCompany         = "Company"
	SysmonAttrOriginalName    = "OriginalFileName"
	SysmonAttrHashes          = "Hashes"
	SysmonAttrSigned          = "Signed"
	SysmonAttrSignature       = "Signature"
	SysmonAttrSignatureStatus = "SignatureStatus"
	SysmonAttrEventID         = "EventID"
	SysmonAttrChannel         = "Channel"

	SysmonChannelDefault = "Microsoft-Windows-Sysmon/Operational"
)

// SysmonImageLoadEvent renders LoadedDriver as Sysmon EID 6 attributes
// suitable for direct attachment to an OTLP log record body or a JSON
// envelope consumed by SIEM rules.
//
// All values are strings (Sysmon's wire form), keeping downstream consumers
// type-agnostic. Empty fields are omitted so the resulting map preserves
// Sysmon's "absent rather than empty" convention.
//
// Mapping rules:
//   - UtcTime:           CollectedAt formatted as RFC3339 (Sysmon uses local
//     time but our agent emits UTC throughout).
//   - ImageLoaded:       LoadedDriver.Path verbatim — the kernel-visible
//     path of the .sys/.ko/.kext binary.
//   - FileVersion/Product/Company:
//     Version / DisplayName / Vendor where present.
//   - Hashes:            "SHA256=...,IMPHASH=...,Authentihash=..." in stable
//     key order. Authentihash is a non-Sysmon extension
//     but every modern Sysmon SIEM rule already accepts
//     the trailing extra-key form.
//   - Signed:            "true" when SignatureState in {valid, catalog,
//     expired, revoked}, else "false".
//   - Signature:         Signer (cert subject CN) when present, otherwise
//     the friendly Vendor name.
//   - SignatureStatus:   one of Sysmon's documented status strings derived
//     from the LoadedDriver SignatureState constant.
func SysmonImageLoadEvent(d LoadedDriver) map[string]string {
	out := map[string]string{
		SysmonAttrEventID: "6",
		SysmonAttrChannel: SysmonChannelDefault,
		SysmonAttrUTCTime: d.CollectedAt.UTC().Format(time.RFC3339),
	}
	if d.Path != "" {
		out[SysmonAttrImageLoaded] = d.Path
	} else if d.Name != "" {
		// Some Linux/macOS rows have no path — fall back to module name so
		// the SIEM rule has something to key on.
		out[SysmonAttrImageLoaded] = d.Name
	}
	if d.Version != "" {
		out[SysmonAttrFileVersion] = d.Version
	}
	if d.Description != "" {
		out[SysmonAttrDescription] = d.Description
	}
	if d.DisplayName != "" {
		out[SysmonAttrProduct] = d.DisplayName
	}
	if d.Vendor != "" {
		out[SysmonAttrCompany] = d.Vendor
	}
	if d.Name != "" {
		out[SysmonAttrOriginalName] = d.Name
	}
	if h := sysmonHashesField(d); h != "" {
		out[SysmonAttrHashes] = h
	}
	out[SysmonAttrSigned] = sysmonSignedFlag(d.SignatureState)
	out[SysmonAttrSignature] = sysmonSigner(d)
	out[SysmonAttrSignatureStatus] = SysmonSignatureStatus(d.SignatureState)
	return out
}

// SysmonSignatureStatus translates a LoadedDriver SignatureState constant to
// Sysmon's documented SignatureStatus strings (the values surfaced by
// Sysmon's own driver-load events on Windows). Unknown maps to "Unavailable",
// matching Sysmon's behaviour when the catalog is missing.
func SysmonSignatureStatus(state string) string {
	switch state {
	case SignatureValid, SignatureCatalog:
		return "Valid"
	case SignatureExpired:
		return "Expired"
	case SignatureRevoked:
		return "Revoked"
	case SignatureUnsigned:
		return "Unsigned"
	case SignatureUnknown, "":
		return "Unavailable"
	}
	return "Unavailable"
}

// sysmonSignedFlag returns "true" for any signature state Sysmon would
// consider signed (even if expired or revoked the file *is* signed —
// matches the Sysmon EID 6 schema).
func sysmonSignedFlag(state string) string {
	switch state {
	case SignatureValid, SignatureCatalog, SignatureExpired, SignatureRevoked:
		return "true"
	}
	return "false"
}

// sysmonSigner returns the subject CN of the code-signing cert when
// available, falling back to the vendor / company string. Empty when both
// are missing — Sysmon emits the literal "<unknown>" in that case but the
// OTel attribute layer prefers an explicit empty value.
func sysmonSigner(d LoadedDriver) string {
	if d.Signer != "" {
		return d.Signer
	}
	if d.Vendor != "" {
		return d.Vendor
	}
	return ""
}

// sysmonHashesField builds the comma-separated "ALGO=HEX,..." string Sysmon
// uses for the Hashes column. Output is sorted by algorithm name so consumer
// rules can match by exact substring without brittle ordering assumptions.
func sysmonHashesField(d LoadedDriver) string {
	parts := []string{}
	if d.Authentihash != "" {
		parts = append(parts, "Authentihash="+strings.ToUpper(d.Authentihash))
	}
	if d.ImportHash != "" {
		parts = append(parts, "IMPHASH="+strings.ToUpper(d.ImportHash))
	}
	if d.OnDiskSHA256 != "" {
		parts = append(parts, "SHA256="+strings.ToUpper(d.OnDiskSHA256))
	}
	return strings.Join(parts, ",")
}
