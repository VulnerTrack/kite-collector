package dashboard

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

func collectPKICertificates(
	ctx context.Context,
	deps onboardingDeps,
) ([]pkiCertificateSummary, int, string, bool) {
	if deps.PKIReader == nil || deps.PKIOperatorToken == nil || strings.TrimSpace(deps.PKIEndpoint) == "" {
		return nil, 0, "PKI certificate inventory is unavailable in this dashboard mode", false
	}
	token, err := deps.PKIOperatorToken(ctx)
	if err != nil {
		return nil, 0, "Sign in to VulnerTrack to load tenant certificates", true
	}
	certificates, total, err := deps.PKIReader.List(ctx, deps.PKIEndpoint, token)
	if err != nil {
		if errors.Is(err, errPKICertificateSignInRequired) {
			return nil, 0, "Your VulnerTrack session expired; sign in again to load certificates", true
		}
		return nil, 0, err.Error(), false
	}
	certificates = latestActiveComputerCertificates(certificates)
	total = len(certificates)
	for i := range certificates {
		certificates[i].StatusClass = pkiCertificateStatusClass(certificates[i].Status)
	}
	return certificates, total, "", false
}

// latestActiveComputerCertificates keeps the one certificate operators need
// for each enrolled computer: the newest active row identified by agent_code.
// CA/service rows without an agent_code and historical revoked/superseded rows
// are intentionally excluded from the Observability inventory.
func latestActiveComputerCertificates(certificates []pkiCertificateSummary) []pkiCertificateSummary {
	latest := make(map[string]pkiCertificateSummary)
	for _, certificate := range certificates {
		if !strings.EqualFold(strings.TrimSpace(certificate.Status), "active") {
			continue
		}
		agentCode := strings.TrimSpace(certificate.AgentCode)
		if agentCode == "" {
			continue
		}
		key := strings.ToLower(agentCode)
		current, exists := latest[key]
		if !exists || certificateIssuedAfter(certificate, current) {
			latest[key] = certificate
		}
	}

	filtered := make([]pkiCertificateSummary, 0, len(latest))
	for _, certificate := range latest {
		filtered = append(filtered, certificate)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return certificateIssuedAfter(filtered[i], filtered[j])
	})
	return filtered
}

func certificateIssuedAfter(candidate, current pkiCertificateSummary) bool {
	candidateTime, candidateErr := time.Parse(time.RFC3339Nano, candidate.IssuedAt)
	currentTime, currentErr := time.Parse(time.RFC3339Nano, current.IssuedAt)
	if candidateErr == nil && currentErr == nil {
		return candidateTime.After(currentTime)
	}
	// ClickHouse DateTime64 strings remain lexicographically sortable when an
	// older API version omits an RFC3339 timezone suffix.
	return candidate.IssuedAt > current.IssuedAt
}

func pkiCertificateStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active", "valid":
		return "badge-green"
	case "revoked", "expired", "superseded":
		return "badge-red"
	case "pending":
		return "badge-blue"
	default:
		return "badge-gray"
	}
}

func handlePKICertificateInventory(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	view := observabilityView{}
	view.Certificates, view.CertificateTotal, view.CertificatesError,
		view.CertificatesSignInRequired = collectPKICertificates(r.Context(), deps)
	view.HasCertificates = len(view.Certificates) > 0

	var body bytes.Buffer
	if err := pkiCertificateInventoryTmpl.Execute(&body, view); err != nil {
		http.Error(w, "could not render certificate inventory", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}

func handlePKICertificateDetail(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	certificateID := strings.TrimSpace(r.PathValue("id"))
	if _, err := uuid.Parse(certificateID); err != nil {
		http.Error(w, "invalid certificate ID", http.StatusBadRequest)
		return
	}
	if deps.PKIReader == nil || deps.PKIOperatorToken == nil {
		http.Error(w, "PKI certificate inventory is unavailable", http.StatusServiceUnavailable)
		return
	}
	token, err := deps.PKIOperatorToken(r.Context())
	if err != nil {
		http.Error(w, "sign in to VulnerTrack to inspect certificates", http.StatusUnauthorized)
		return
	}
	detail, err := deps.PKIReader.Get(r.Context(), deps.PKIEndpoint, token, certificateID)
	if err != nil {
		if errors.Is(err, errPKICertificateSignInRequired) {
			http.Error(w, "VulnerTrack session expired; sign in again", http.StatusUnauthorized)
			return
		}
		if deps.Logger != nil {
			deps.Logger.Error("observability: load PKI certificate detail",
				"certificate_id", certificateID, "error", err)
		}
		http.Error(w, "could not load certificate detail", http.StatusBadGateway)
		return
	}
	detail.StatusClass = pkiCertificateStatusClass(detail.Status)
	var body bytes.Buffer
	if err := pkiCertificateDetailTmpl.Execute(&body, detail); err != nil {
		http.Error(w, "could not render certificate detail", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}

var pkiCertificateDetailTmpl = template.Must(template.New("pki-certificate-detail").Parse(`
<div class="pki-certificate-detail">
  <div class="observability-table-wrap">
    <table class="kv observability-kv">
      <tr><td>ID</td><td><code>{{.ID}}</code></td></tr>
      <tr><td>Serial number</td><td><code>{{.SerialNumber}}</code></td></tr>
      <tr><td>Subject CN</td><td><code>{{.SubjectCN}}</code></td></tr>
      <tr><td>Subject organization</td><td><code>{{.SubjectOrg}}</code></td></tr>
      <tr><td>Tenant ID</td><td><code>{{.TenantID}}</code></td></tr>
      <tr><td>Issuer CN</td><td><code>{{.IssuerCN}}</code></td></tr>
      <tr><td>SHA-256 fingerprint</td><td><code>{{.FingerprintSHA256}}</code></td></tr>
      <tr><td>Key algorithm</td><td>{{.KeyAlgorithm}}</td></tr>
      <tr><td>Purpose</td><td>{{.Purpose}}</td></tr>
      <tr><td>Status</td><td><span class="badge {{.StatusClass}}">{{.Status}}</span></td></tr>
      <tr><td>Not before</td><td><code>{{.NotBefore}}</code></td></tr>
      <tr><td>Not after</td><td><code>{{.NotAfter}}</code></td></tr>
      <tr><td>Issued at</td><td><code>{{.IssuedAt}}</code></td></tr>
      <tr><td>Revoked at</td><td>{{if .RevokedAt}}<code>{{.RevokedAt}}</code>{{else}}&mdash;{{end}}</td></tr>
      <tr><td>Revocation reason</td><td>{{if .RevocationReason}}{{.RevocationReason}}{{else}}&mdash;{{end}}</td></tr>
      <tr><td>Parent CA ID</td><td>{{if .ParentCAID}}<code>{{.ParentCAID}}</code>{{else}}&mdash;{{end}}</td></tr>
      <tr><td>Agent code</td><td>{{if .AgentCode}}<code>{{.AgentCode}}</code>{{else}}&mdash;{{end}}</td></tr>
      <tr><td>Sync version</td><td>{{if .SyncVersion}}<code>{{.SyncVersion}}</code>{{else}}<span class="muted small">not returned by this PKI version</span>{{end}}</td></tr>
    </table>
  </div>
  <details>
    <summary>Certificate PEM</summary>
    <pre class="failure-diagnostic">{{.CertPEM}}</pre>
  </details>
  <details>
    <summary>Certificate signing request (CSR)</summary>
    {{if .CSRPEM}}<pre class="failure-diagnostic">{{.CSRPEM}}</pre>{{else}}<p class="muted small">No CSR stored for this certificate.</p>{{end}}
  </details>
  <p class="muted small">PKI never returns or stores the certificate private key.</p>
</div>`))

var pkiCertificateInventoryTmpl = template.Must(template.New("pki-certificate-inventory").Parse(`
{{if .CertificatesError}}
  <div class="pki-certificate-notice" data-kind="{{if .CertificatesSignInRequired}}auth{{else}}pki{{end}}">
    <strong>{{if .CertificatesSignInRequired}}Sign in required{{else}}PKI unavailable{{end}}:</strong>
    <span>{{.CertificatesError}}</span>
    {{if .CertificatesSignInRequired}}<a class="btn btn-ghost" href="/kite-login?dashboard=%2Fobservability">Sign in &rarr;</a>{{end}}
  </div>
{{else if .HasCertificates}}
  <p class="muted small">Showing the latest active certificate for each of {{.CertificateTotal}} enrolled computers. Select <strong>Full details</strong> for every <code>pki_certificates</code> field, certificate PEM and CSR.</p>
  <div class="observability-table-wrap">
  <table class="observability-table pki-certificates-table">
    <thead>
      <tr><th>Agent / subject</th><th>Status</th><th>Serial</th><th>Tenant</th><th>Issued</th><th>Expires</th><th>Fingerprint SHA-256</th><th>Details</th></tr>
    </thead>
    <tbody>
    {{range .Certificates}}
      <tr>
        <td>{{if .AgentCode}}<code>{{.AgentCode}}</code>{{else}}<code>{{.SubjectCN}}</code>{{end}}<br><span class="muted small">{{.Purpose}} &middot; {{.KeyAlgorithm}}</span></td>
        <td><span class="badge {{.StatusClass}}">{{.Status}}</span></td>
        <td><code>{{.SerialNumber}}</code></td>
        <td><code>{{.TenantID}}</code></td>
        <td><code>{{.IssuedAt}}</code></td>
        <td><code>{{.NotAfter}}</code></td>
        <td><code>{{.FingerprintSHA256}}</code></td>
        <td><button class="btn btn-ghost" type="button"
                    hx-get="/fragments/observability/certificates/{{.ID}}"
                    hx-target="#certificate-detail-{{.ID}}"
                    hx-swap="innerHTML">Full details</button></td>
      </tr>
      <tr><td colspan="8" id="certificate-detail-{{.ID}}"></td></tr>
    {{end}}
    </tbody>
  </table>
  </div>
{{else}}
  <p class="muted">No PKI certificates have been issued for this organization yet. Certificates from individual and mass enrollments will appear here.</p>
{{end}}`))
