package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKIHTTPCertificateReaderListsEveryFleetCertificatePage(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer operator-jwt", r.Header.Get("Authorization"))
		assert.Equal(t, "/pki/certificates", r.URL.Path)
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		require.NoError(t, err)
		requests++
		row := pkiCertificateSummary{
			ID:        "019d0000-0000-7000-8000-00000000000" + strconv.Itoa(offset+1),
			AgentCode: "kite-fleet-" + strconv.Itoa(offset+1),
			TenantID:  "tenant-1",
			Status:    "active",
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []pkiCertificateSummary{row}, "total": 2})
	}))
	defer server.Close()

	reader := newPKIHTTPCertificateReader()
	certificates, total, err := reader.List(context.Background(), server.URL, "operator-jwt")
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, certificates, 2)
	assert.Equal(t, "kite-fleet-1", certificates[0].AgentCode)
	assert.Equal(t, "kite-fleet-2", certificates[1].AgentCode)
	assert.Equal(t, 2, requests)
}

func TestPKIHTTPCertificateReaderLoadsCompleteDetail(t *testing.T) {
	t.Parallel()
	certificateID := "019d0000-0000-7000-8000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pki/certificates/"+certificateID, r.URL.Path)
		_ = json.NewEncoder(w).Encode(pkiCertificateDetail{
			pkiCertificateSummary: pkiCertificateSummary{
				ID: certificateID, SerialNumber: "abc123", SubjectCN: "kite-pc-01",
				SubjectOrg: "tenant-1", TenantID: "tenant-1", IssuerCN: "Vulnertrack Root CA",
				FingerprintSHA256: "deadbeef", KeyAlgorithm: "EC", Purpose: "client",
				Status: "active", AgentCode: "kite-pc-01",
			},
			RevocationReason: "", CertPEM: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
			CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----",
			ParentCAID: "019d0000-0000-7000-8000-000000000099", SyncVersion: 42,
		})
	}))
	defer server.Close()

	detail, err := newPKIHTTPCertificateReader().Get(context.Background(), server.URL, "operator-jwt", certificateID)
	require.NoError(t, err)
	assert.Equal(t, "kite-pc-01", detail.AgentCode)
	assert.Contains(t, detail.CertPEM, "BEGIN CERTIFICATE")
	assert.Contains(t, detail.CSRPEM, "BEGIN CERTIFICATE REQUEST")
	assert.Equal(t, uint64(42), detail.SyncVersion)
}

func TestCollectPKICertificatesIncludesMassEnrollmentRows(t *testing.T) {
	t.Parallel()
	reader := &fakePKICertificateReader{list: []pkiCertificateSummary{
		{ID: "1", AgentCode: "kite-pc-01", Status: "active"},
		{ID: "2", AgentCode: "kite-pc-02", Status: "revoked"},
	}}
	certificates, total, message, signIn := collectPKICertificates(context.Background(), onboardingDeps{
		PKIReader:        reader,
		PKIOperatorToken: func(context.Context) (string, error) { return "operator-jwt", nil },
		PKIEndpoint:      "https://pki.example.test",
	})
	assert.Len(t, certificates, 2)
	assert.Equal(t, 2, total)
	assert.Empty(t, message)
	assert.False(t, signIn)
	assert.Equal(t, "badge-green", certificates[0].StatusClass)
	assert.Equal(t, "badge-red", certificates[1].StatusClass)
}

func TestObservabilityCertificateSectionRendersEveryMassEnrollmentAgent(t *testing.T) {
	t.Parallel()
	view := observabilityView{
		Certificates: []pkiCertificateSummary{
			{ID: "1", AgentCode: "kite-fleet-pc-01", Status: "active", StatusClass: "badge-green"},
			{ID: "2", AgentCode: "kite-fleet-pc-02", Status: "active", StatusClass: "badge-green"},
		},
		CertificateTotal: 2,
		HasCertificates:  true,
		Freshness:        newFreshness(true),
	}
	var body bytes.Buffer
	require.NoError(t, observabilityTmpl.Execute(&body, view))
	assert.Contains(t, body.String(), "Kite certificates")
	assert.Contains(t, body.String(), "kite-fleet-pc-01")
	assert.Contains(t, body.String(), "kite-fleet-pc-02")
	assert.Contains(t, body.String(), "Showing all 2 certificates")
}

func TestPKICertificateDetailFragmentRendersAllPublicMaterial(t *testing.T) {
	t.Parallel()
	certificateID := "019d0000-0000-7000-8000-000000000001"
	reader := &fakePKICertificateReader{detail: pkiCertificateDetail{
		pkiCertificateSummary: pkiCertificateSummary{
			ID: certificateID, SerialNumber: "abc123", SubjectCN: "kite-pc-01",
			TenantID: "tenant-1", Status: "active", FingerprintSHA256: "deadbeef",
		},
		CertPEM: "PUBLIC-CERT-PEM", CSRPEM: "PUBLIC-CSR-PEM", SyncVersion: 9,
	}}
	req := httptest.NewRequest(http.MethodGet, "/fragments/observability/certificates/"+certificateID, nil)
	req.SetPathValue("id", certificateID)
	recorder := httptest.NewRecorder()
	handlePKICertificateDetail(recorder, req, onboardingDeps{
		PKIReader:        reader,
		PKIOperatorToken: func(context.Context) (string, error) { return "operator-jwt", nil },
		PKIEndpoint:      "https://pki.example.test",
	})

	assert.Equal(t, http.StatusOK, recorder.Code)
	body := recorder.Body.String()
	for _, expected := range []string{"abc123", "kite-pc-01", "tenant-1", "deadbeef", "PUBLIC-CERT-PEM", "PUBLIC-CSR-PEM", ">9<"} {
		assert.True(t, strings.Contains(body, expected), body)
	}
}

type fakePKICertificateReader struct {
	list   []pkiCertificateSummary
	detail pkiCertificateDetail
}

func (f *fakePKICertificateReader) List(context.Context, string, string) ([]pkiCertificateSummary, int, error) {
	return f.list, len(f.list), nil
}

func (f *fakePKICertificateReader) Get(context.Context, string, string, string) (pkiCertificateDetail, error) {
	return f.detail, nil
}
