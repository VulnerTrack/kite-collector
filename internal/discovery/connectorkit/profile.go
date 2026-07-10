package connectorkit

// TLS mode values for SecurityProfile.TLSMode, mirroring the enum on the
// ConnectorSecurityProfile ontology entity (4.1.4).
const (
	TLSModeSystemCA = "system_ca"
	TLSModeCustomCA = "custom_ca"
	TLSModeInsecure = "insecure"
)

// Credential privilege-tier values for SecurityProfile.CredentialPrivilegeTier,
// mirroring the credential_privilege_tier enum on the ConnectorSecurityProfile
// ontology entity (RFC-0137 4.1.1). This captures the blast-radius differentiator
// that motivated RFC-0137's P0 priority: these connectors' credentials span a far
// wider privilege range than the MDM/CMDB ones connectorkit was first built for.
// The tier is descriptive only — it does not contribute to HardeningScore.
const (
	// PrivilegeTierIdentityDirectoryAdmin — Entra Graph API app-registration
	// scope, typically tenant-wide.
	PrivilegeTierIdentityDirectoryAdmin = "identity_directory_admin"
	// PrivilegeTierDNSZoneAdmin — cloud-account/subscription DNS management-plane
	// scope (route53, cloudflare_dns, azure_dns, gcp_cloud_dns).
	PrivilegeTierDNSZoneAdmin = "dns_zone_admin"
	// PrivilegeTierDeviceManagement — reserved for RFC-0135's MDM sources.
	PrivilegeTierDeviceManagement = "device_management"
	// PrivilegeTierAssetRegistry — reserved for RFC-0135's CMDB sources.
	PrivilegeTierAssetRegistry = "asset_registry"
	// PrivilegeTierUnknown is the default when a connector does not classify its
	// credential blast radius.
	PrivilegeTierUnknown = "unknown"
)

// SecurityProfile is the code-derived hardening posture of a single connector
// instance: which internal/safenet and internal/safety primitives actively
// protect it. It is computed at startup from the connector's actual wiring
// (not self-reported), turning "is this connector hardened?" from a
// source-reading exercise into a queryable fact (ConnectorSecurityProfile).
type SecurityProfile struct {
	SourceName string
	TLSMode    string

	// CredentialPrivilegeTier classifies the blast radius of the credential this
	// connector holds (RFC-0137 4.1.1). It is descriptive metadata, not one of
	// the six scored booleans, so it never affects HardeningScore. Defaults to
	// PrivilegeTierUnknown for connectors that do not classify it. Kept with the
	// other string fields so the struct stays optimally field-aligned.
	CredentialPrivilegeTier string

	HardeningScore         float32
	EndpointValidated      bool
	PathSegmentsSanitized  bool
	PaginationGuarded      bool
	CredentialsZeroed      bool
	EnabledFlagRespected   bool
	CircuitBreakerAttached bool
}

// ComputeScore sets HardeningScore to the fraction of the six hardening
// booleans that are true. Per the axiom in RFC 4.2.4, an insecure TLS mode
// structurally caps the achievable score at 5/6 even when all six booleans are
// true, because unverified TLS undermines every other control.
func (p *SecurityProfile) ComputeScore() {
	trueCount := 0
	for _, b := range [...]bool{
		p.EndpointValidated,
		p.PathSegmentsSanitized,
		p.PaginationGuarded,
		p.CredentialsZeroed,
		p.EnabledFlagRespected,
		p.CircuitBreakerAttached,
	} {
		if b {
			trueCount++
		}
	}
	score := float32(trueCount) / 6.0
	if p.TLSMode == TLSModeInsecure {
		if capScore := float32(5) / 6.0; score > capScore {
			score = capScore
		}
	}
	p.HardeningScore = score
}

// AssessConnector builds the SecurityProfile for a connector that was written
// on connectorkit. Using connectorkit at all makes endpoint validation,
// pagination guarding, and the enabled-flag check true by construction; the
// remaining booleans (path-segment sanitization, credential zeroing, TLS mode,
// circuit-breaker attachment) are supplied by the caller from the same startup
// wiring that main.go performs.
//
// It is a thin wrapper over AssessConnectorWithTier that supplies
// PrivilegeTierUnknown, so the ten existing MDM/CMDB consumers keep their
// current five-argument call sites unchanged (RFC-0137 R1: same additive
// wrapper pattern as SafeClient/SafeClientWithTimeout).
func AssessConnector(sourceName string, pathSanitized, credentialsZeroed, circuitBreakerAttached bool, tlsMode string) SecurityProfile {
	return AssessConnectorWithTier(sourceName, pathSanitized, credentialsZeroed,
		circuitBreakerAttached, tlsMode, PrivilegeTierUnknown)
}

// AssessConnectorWithTier is AssessConnector plus an explicit
// credentialPrivilegeTier, recording the blast-radius classification RFC-0137
// 4.1.1 adds. Entra passes PrivilegeTierIdentityDirectoryAdmin and the four
// Cloud DNS connectors pass PrivilegeTierDNSZoneAdmin. The tier is descriptive
// and does not change HardeningScore.
func AssessConnectorWithTier(sourceName string, pathSanitized, credentialsZeroed, circuitBreakerAttached bool, tlsMode, credentialPrivilegeTier string) SecurityProfile {
	if credentialPrivilegeTier == "" {
		credentialPrivilegeTier = PrivilegeTierUnknown
	}
	p := SecurityProfile{
		SourceName:              sourceName,
		TLSMode:                 tlsMode,
		EndpointValidated:       true,
		PathSegmentsSanitized:   pathSanitized,
		PaginationGuarded:       true,
		CredentialsZeroed:       credentialsZeroed,
		EnabledFlagRespected:    true,
		CircuitBreakerAttached:  circuitBreakerAttached,
		CredentialPrivilegeTier: credentialPrivilegeTier,
	}
	p.ComputeScore()
	return p
}
