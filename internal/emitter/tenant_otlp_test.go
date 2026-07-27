package emitter

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	telresource "github.com/vulnertrack/kite-collector/internal/telemetry/resource"
)

// These tests verify the OTel logs half of the tenancy flow: whatever tenant
// the agent enrolled with must surface as the tenant.id resource attribute on
// every emitted OTLP batch. The fake is an in-process OTLP /v1/logs sink
// (startCaptureServer) that records the exact JSON the emitter sends.

const testAgentID = "018f9c2a-7b3d-7a01-8c2e-aaaabbbbcccc"

// decodeResourceAttrs extracts the resource-level attribute map from a
// captured OTLP /v1/logs JSON body.
func decodeResourceAttrs(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var p struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue *string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
		} `json:"resourceLogs"`
	}
	require.NoError(t, json.Unmarshal(body, &p))
	require.Len(t, p.ResourceLogs, 1)
	out := make(map[string]string)
	for _, a := range p.ResourceLogs[0].Resource.Attributes {
		if a.Value.StringValue != nil {
			out[a.Key] = *a.Value.StringValue
		}
	}
	return out
}

// emitOneWithResource emits a single discovery event through an OTLPEmitter
// configured with res, and returns the resource attributes the fake sink saw.
func emitOneWithResource(t *testing.T, res map[string]string) map[string]string {
	t.Helper()
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em, err := NewOTLP(OTLPConfig{Resource: res, Endpoint: endpoint}, "1.2.3")
	require.NoError(t, err)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	require.NoError(t, em.Emit(context.Background(),
		makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)))

	require.Len(t, *reqs, 1)
	return decodeResourceAttrs(t, (*reqs)[0].Body)
}

func TestOTLP_EmitsTenantIDFromResource(t *testing.T) {
	res := telresource.Build(telresource.Config{
		ServiceVersion: "1.2.3",
		TenantID:       "019def78-0000-7000-8000-000000000abc",
		AgentID:        uuid.MustParse(testAgentID),
	})
	attrs := emitOneWithResource(t, res)
	assert.Equal(t, "019def78-0000-7000-8000-000000000abc", attrs["tenant.id"],
		"tenant.id must appear on the OTLP resource of every emitted batch")
}

func TestOTLP_TenantIDFallsBackToUnknown(t *testing.T) {
	res := telresource.Build(telresource.Config{
		ServiceVersion: "1.2.3",
		AgentID:        uuid.MustParse(testAgentID),
		// TenantID intentionally empty.
	})
	attrs := emitOneWithResource(t, res)
	assert.Equal(t, "unknown", attrs["tenant.id"],
		"an un-enrolled agent must emit tenant.id=unknown, never omit it")
}

// tenant.id sits on the redact allowlist, so it must survive the emitter's
// forbidden-key filter while a genuine credential key is stripped.
func TestOTLP_TenantIDSurvivesRedactWhileSecretsStripped(t *testing.T) {
	attrs := emitOneWithResource(t, map[string]string{
		"tenant.id":    "019def78-tenant",
		"service.name": "kite-collector",
		"password":     "hunter2", // forbidden substring -> must be dropped
	})
	assert.Equal(t, "019def78-tenant", attrs["tenant.id"])
	_, hasSecret := attrs["password"]
	assert.False(t, hasSecret, "a forbidden resource key must be stripped before emission")
}

// End-to-end: the tenant asserted on the mTLS certificate Organization — the
// same field peerTenantID and MTLSAuth read on the ingest/read paths — is the
// value that lands in the OTLP resource's tenant.id.
func TestOTLP_CertOrganizationFlowsToTenantID(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{Organization: []string{"019def78-cert-tenant"}}}
	require.NotEmpty(t, cert.Subject.Organization)
	tenantFromCert := cert.Subject.Organization[0]

	res := telresource.Build(telresource.Config{
		ServiceVersion: "1.2.3",
		TenantID:       tenantFromCert,
		AgentID:        uuid.MustParse(testAgentID),
	})
	attrs := emitOneWithResource(t, res)
	assert.Equal(t, "019def78-cert-tenant", attrs["tenant.id"])
}
