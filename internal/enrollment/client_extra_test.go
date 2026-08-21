package enrollment

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Enroll / EnrollWithToken response handling edges
// -------------------------------------------------------------------------

func TestEnroll_BodyReadFailure(t *testing.T) {
	c := NewClient(nil)
	c.http = &stubDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(errReader{}),
	}}

	_, err := c.Enroll(context.Background(), "agent-1", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read response")
}

func TestEnroll_MalformedSuccessResponse(t *testing.T) {
	c := NewClient(nil)
	c.http = &stubDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(`{"status":`)),
	}}

	_, err := c.Enroll(context.Background(), "agent-1", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

// TestEnroll_Accepts200OK pins the status boundary: both 200 and 201 are
// success (201 is exercised elsewhere; 202 would be a rejection).
func TestEnroll_Accepts200OK(t *testing.T) {
	c := NewClient(nil)
	c.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		resp := issueEnrollmentResponse(t, body["csr_pem"], nil)
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		return resp, nil
	}}

	result, err := c.Enroll(context.Background(), "kite-machine-1", "jwt")
	require.NoError(t, err)
	assert.Equal(t, "enrolled", result.Status)
	assert.Equal(t, "cert-1", result.CertificateID)
}

func TestEnrollWithToken_BodyReadFailure(t *testing.T) {
	c := NewClient(nil)
	c.http = &stubDoer{resp: &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(errReader{}),
	}}

	_, err := c.EnrollWithToken(context.Background(), "agent-1", "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read response")
}

// -------------------------------------------------------------------------
// validateEnrollmentCertificate
// -------------------------------------------------------------------------

func TestValidateEnrollmentCertificate_ErrorPaths(t *testing.T) {
	material, caPEM, issueLeaf := newRenewalMaterialFixture(t)
	leafPEM := issueLeaf(20, time.Now().Add(24*time.Hour))
	otherKey := newECDSAKey(t)
	unrelatedCA := string(selfSignedCertPEM(t, "Unrelated CA", otherKey))

	tests := []struct {
		name      string
		agentCode string
		certPEM   string
		caPEM     string
		wantErr   string
	}{
		{
			name:      "wrong PEM block type",
			agentCode: "kite-agent-1",
			certPEM: string(pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: []byte("x"),
			})),
			caPEM:   caPEM,
			wantErr: "response contains no client certificate",
		},
		{
			name:      "certificate bad DER",
			agentCode: "kite-agent-1",
			certPEM: string(pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: []byte("junk"),
			})),
			caPEM:   caPEM,
			wantErr: "parse client certificate",
		},
		{
			name:      "common name mismatch",
			agentCode: "other-agent",
			certPEM:   leafPEM,
			caPEM:     caPEM,
			wantErr:   `certificate common name mismatch: got "kite-agent-1", want "other-agent"`,
		},
		{
			name:      "unusable CA bundle",
			agentCode: "kite-agent-1",
			certPEM:   leafPEM,
			caPEM:     "garbage",
			wantErr:   "response contains no valid CA certificate",
		},
		{
			name:      "chain does not verify",
			agentCode: "kite-agent-1",
			certPEM:   leafPEM,
			caPEM:     unrelatedCA,
			wantErr:   "verify client certificate chain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnrollmentCertificate(
				tt.agentCode,
				[]byte(tt.certPEM),
				[]byte(tt.caPEM),
				material.signer,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// -------------------------------------------------------------------------
// StoreCertificates error paths
// -------------------------------------------------------------------------

func TestStoreCertificates_MkdirFailure(t *testing.T) {
	base := t.TempDir()
	blocking := filepath.Join(base, "not-a-dir")
	require.NoError(t, os.WriteFile(blocking, []byte("x"), 0o600))

	err := StoreCertificates(filepath.Join(blocking, "certs"), &Result{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create credential dir")
}

func TestStoreCertificates_WriteFailure(t *testing.T) {
	dir := t.TempDir()
	// Every credential path is a directory, so whichever file the map
	// iteration picks first fails its atomic rename.
	for _, name := range []string{"ca.pem", "agent.pem", "agent-key.pem"} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0o700))
	}

	err := StoreCertificates(dir, &Result{
		CACertificate:     []byte("ca"),
		ClientCertificate: []byte("cert"),
		ClientKey:         []byte("key"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write ")
	assert.Contains(t, err.Error(), "replace credential")
}
