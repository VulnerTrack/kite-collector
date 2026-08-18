package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const pkiCertificatePageSize = 1000

var errPKICertificateSignInRequired = errors.New("VulnerTrack sign-in required to load PKI certificates")

// pkiCertificateSummary is the tenant-scoped row returned by the PKI list
// endpoint. A fleet enrollment issues one certificate per computer; fetching
// every page makes all of those rows visible instead of showing only this
// controller's local agent.pem.
type pkiCertificateSummary struct {
	ID                string `json:"id"`
	SerialNumber      string `json:"serial_number"`
	SubjectCN         string `json:"subject_cn"`
	SubjectOrg        string `json:"subject_org"`
	TenantID          string `json:"tenant_id"`
	IssuerCN          string `json:"issuer_cn"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	KeyAlgorithm      string `json:"key_algorithm"`
	Purpose           string `json:"purpose"`
	Status            string `json:"status"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	IssuedAt          string `json:"issued_at"`
	AgentCode         string `json:"agent_code"`
	StatusClass       string `json:"-"`
}

// pkiCertificateDetail mirrors every column exposed by pki_certificates. PEM
// and CSR material is public cryptographic material; private keys are never
// stored by PKI and therefore cannot be returned by this surface.
type pkiCertificateDetail struct {
	pkiCertificateSummary
	RevokedAt        string `json:"revoked_at"`
	RevocationReason string `json:"revocation_reason"`
	CertPEM          string `json:"cert_pem"`
	CSRPEM           string `json:"csr_pem"`
	ParentCAID       string `json:"parent_ca_id"`
	SyncVersion      uint64 `json:"sync_version,omitempty"`
}

type pkiCertificateReader interface {
	List(ctx context.Context, endpoint, operatorToken string) ([]pkiCertificateSummary, int, error)
	Get(ctx context.Context, endpoint, operatorToken, certificateID string) (pkiCertificateDetail, error)
}

type pkiHTTPCertificateReader struct {
	client       *http.Client
	cacheKey     string
	cacheExpires time.Time
	cached       []pkiCertificateSummary
	cachedTotal  int
	cacheMu      sync.Mutex
}

func newPKIHTTPCertificateReader() *pkiHTTPCertificateReader {
	return &pkiHTTPCertificateReader{client: &http.Client{Timeout: 20 * time.Second}}
}

func (r *pkiHTTPCertificateReader) List(
	ctx context.Context,
	endpoint, operatorToken string,
) ([]pkiCertificateSummary, int, error) {
	if strings.TrimSpace(operatorToken) == "" {
		return nil, 0, errPKICertificateSignInRequired
	}
	tokenDigest := sha256.Sum256([]byte(operatorToken))
	cacheKey := strings.TrimRight(endpoint, "/") + fmt.Sprintf("|%x", tokenDigest)
	r.cacheMu.Lock()
	if cacheKey == r.cacheKey && time.Now().Before(r.cacheExpires) {
		cached := append([]pkiCertificateSummary(nil), r.cached...)
		total := r.cachedTotal
		r.cacheMu.Unlock()
		return cached, total, nil
	}
	r.cacheMu.Unlock()
	all := make([]pkiCertificateSummary, 0)
	total := 0
	for offset := 0; ; {
		listURL := strings.TrimRight(endpoint, "/") + "/pki/certificates?limit=" +
			strconv.Itoa(pkiCertificatePageSize) + "&offset=" + strconv.Itoa(offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("create PKI certificate list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+operatorToken)
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request PKI certificates: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, 0, fmt.Errorf("read PKI certificate list: %w", readErr)
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, 0, errPKICertificateSignInRequired
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("PKI certificate list failed (%s)", resp.Status)
		}
		var page struct {
			Data  []pkiCertificateSummary `json:"data"`
			Total int                     `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, 0, fmt.Errorf("decode PKI certificate list: %w", err)
		}
		total = page.Total
		all = append(all, page.Data...)
		offset += len(page.Data)
		if len(page.Data) == 0 || offset >= page.Total {
			break
		}
	}
	r.cacheMu.Lock()
	r.cacheKey = cacheKey
	r.cacheExpires = time.Now().Add(30 * time.Second)
	r.cached = append(r.cached[:0], all...)
	r.cachedTotal = total
	r.cacheMu.Unlock()
	return all, total, nil
}

func (r *pkiHTTPCertificateReader) Get(
	ctx context.Context,
	endpoint, operatorToken, certificateID string,
) (pkiCertificateDetail, error) {
	if strings.TrimSpace(operatorToken) == "" {
		return pkiCertificateDetail{}, errPKICertificateSignInRequired
	}
	detailURL := strings.TrimRight(endpoint, "/") + "/pki/certificates/" + url.PathEscape(certificateID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, nil)
	if err != nil {
		return pkiCertificateDetail{}, fmt.Errorf("create PKI certificate detail request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	resp, err := r.client.Do(req)
	if err != nil {
		return pkiCertificateDetail{}, fmt.Errorf("request PKI certificate detail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if readErr != nil {
		return pkiCertificateDetail{}, fmt.Errorf("read PKI certificate detail: %w", readErr)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return pkiCertificateDetail{}, errPKICertificateSignInRequired
	}
	if resp.StatusCode != http.StatusOK {
		return pkiCertificateDetail{}, fmt.Errorf("PKI certificate detail failed (%s)", resp.Status)
	}
	var detail pkiCertificateDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return pkiCertificateDetail{}, fmt.Errorf("decode PKI certificate detail: %w", err)
	}
	return detail, nil
}
