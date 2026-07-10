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
}
