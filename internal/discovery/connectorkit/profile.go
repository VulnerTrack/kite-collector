package connectorkit

// TLS mode values for SecurityProfile.TLSMode, mirroring the enum on the
// ConnectorSecurityProfile ontology entity (4.1.4).
const (
	TLSModeSystemCA = "system_ca"
	TLSModeCustomCA = "custom_ca"
	TLSModeInsecure = "insecure"
)

// SecurityProfile is the code-derived hardening posture of a single connector
// instance: which internal/safenet and internal/safety primitives actively
// protect it. It is computed at startup from the connector's actual wiring
// (not self-reported), turning "is this connector hardened?" from a
// source-reading exercise into a queryable fact (ConnectorSecurityProfile).
type SecurityProfile struct {
	SourceName             string
	TLSMode                string
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
func AssessConnector(sourceName string, pathSanitized, credentialsZeroed, circuitBreakerAttached bool, tlsMode string) SecurityProfile {
	p := SecurityProfile{
		SourceName:             sourceName,
		TLSMode:                tlsMode,
		EndpointValidated:      true,
		PathSegmentsSanitized:  pathSanitized,
		PaginationGuarded:      true,
		CredentialsZeroed:      credentialsZeroed,
		EnabledFlagRespected:   true,
		CircuitBreakerAttached: circuitBreakerAttached,
	}
	p.ComputeScore()
	return p
}
