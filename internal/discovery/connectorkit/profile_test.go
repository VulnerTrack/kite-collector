package connectorkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeScore_None(t *testing.T) {
	p := SecurityProfile{}
	p.ComputeScore()
	assert.Equal(t, float32(0), p.HardeningScore)
}

func TestComputeScore_All(t *testing.T) {
	p := SecurityProfile{
		TLSMode:                TLSModeSystemCA,
		EndpointValidated:      true,
		PathSegmentsSanitized:  true,
		PaginationGuarded:      true,
		CredentialsZeroed:      true,
		EnabledFlagRespected:   true,
		CircuitBreakerAttached: true,
	}
	p.ComputeScore()
	assert.Equal(t, float32(1), p.HardeningScore)
}

func TestComputeScore_InsecureCap(t *testing.T) {
	// All six booleans true, but insecure TLS caps the score at 5/6.
	p := SecurityProfile{
		TLSMode:                TLSModeInsecure,
		EndpointValidated:      true,
		PathSegmentsSanitized:  true,
		PaginationGuarded:      true,
		CredentialsZeroed:      true,
		EnabledFlagRespected:   true,
		CircuitBreakerAttached: true,
	}
	p.ComputeScore()
	assert.InDelta(t, 5.0/6.0, p.HardeningScore, 0.0001)
}

func TestComputeScore_Partial(t *testing.T) {
	p := SecurityProfile{
		TLSMode:              TLSModeSystemCA,
		EndpointValidated:    true,
		PaginationGuarded:    true,
		EnabledFlagRespected: true,
	}
	p.ComputeScore()
	assert.InDelta(t, 0.5, p.HardeningScore, 0.0001)
}

func TestAssessConnector(t *testing.T) {
	p := AssessConnector("kandji", true, true, true, TLSModeSystemCA)
	assert.Equal(t, "kandji", p.SourceName)
	assert.True(t, p.EndpointValidated)
	assert.True(t, p.PaginationGuarded)
	assert.True(t, p.EnabledFlagRespected)
	assert.True(t, p.PathSegmentsSanitized)
	assert.True(t, p.CredentialsZeroed)
	assert.True(t, p.CircuitBreakerAttached)
	assert.Equal(t, float32(1), p.HardeningScore)

	// A connector wired without a circuit breaker scores below 1.0.
	p = AssessConnector("kandji", true, true, false, TLSModeSystemCA)
	assert.InDelta(t, 5.0/6.0, p.HardeningScore, 0.0001)

	// The five-argument AssessConnector defaults the tier to unknown, keeping
	// the ten existing MDM/CMDB call sites unchanged (RFC-0137 R1).
	assert.Equal(t, PrivilegeTierUnknown, p.CredentialPrivilegeTier)
}

func TestAssessConnectorWithTier(t *testing.T) {
	// RFC-0137 4.1.1: Entra's credential is tenant-wide identity-directory scope.
	p := AssessConnectorWithTier("entra", true, true, true, TLSModeSystemCA,
		PrivilegeTierIdentityDirectoryAdmin)
	assert.Equal(t, "entra", p.SourceName)
	assert.Equal(t, PrivilegeTierIdentityDirectoryAdmin, p.CredentialPrivilegeTier)

	// The tier is descriptive metadata: it does not change the score, which
	// stays 1.0 for a fully-hardened connector.
	assert.Equal(t, float32(1), p.HardeningScore)

	// The four Cloud DNS connectors share the dns_zone_admin tier.
	p = AssessConnectorWithTier("route53", true, true, true, TLSModeSystemCA,
		PrivilegeTierDNSZoneAdmin)
	assert.Equal(t, PrivilegeTierDNSZoneAdmin, p.CredentialPrivilegeTier)
	assert.Equal(t, float32(1), p.HardeningScore)
}

func TestAssessConnectorWithTier_EmptyDefaultsToUnknown(t *testing.T) {
	p := AssessConnectorWithTier("x", true, true, true, TLSModeSystemCA, "")
	assert.Equal(t, PrivilegeTierUnknown, p.CredentialPrivilegeTier)
}
