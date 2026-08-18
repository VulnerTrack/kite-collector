package dashboard

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"
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
	certificates = latestActiveComputerCertificate(certificates, kiteAgentCode())
	total = len(certificates)
	for i := range certificates {
		certificates[i].StatusClass = pkiCertificateStatusClass(certificates[i].Status)
	}
	return certificates, total, "", false
}

// latestActiveComputerCertificate keeps exactly one row: the newest active
// certificate whose agent_code belongs to this local computer. Every Kite
// installation therefore shows its own identity instead of another computer
// from the same tenant. CA/service and historical rows are excluded.
func latestActiveComputerCertificate(certificates []pkiCertificateSummary, localAgentCode string) []pkiCertificateSummary {
	localAgentCode = strings.TrimSpace(localAgentCode)
	if localAgentCode == "" {
		return nil
	}
	var latest pkiCertificateSummary
	found := false
	for _, certificate := range certificates {
		if !strings.EqualFold(strings.TrimSpace(certificate.Status), "active") {
			continue
		}
		agentCode := strings.TrimSpace(certificate.AgentCode)
		if !strings.EqualFold(agentCode, localAgentCode) {
			continue
		}
		if !found || certificateIssuedAfter(certificate, latest) {
			latest = certificate
			found = true
		}
	}
	if !found {
		return nil
	}
	return []pkiCertificateSummary{latest}
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
{{define "detailCopy"}}{{if .}}<button type="button" class="pki-copy-button" data-copy="{{.}}" onclick="copyPKIValue(this)" title="Copy value" aria-label="Copy value to clipboard"><svg class="pki-copy-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8h11v11H8z"></path><path d="M5 16H4V5h11v1"></path></svg><svg class="pki-copy-check" viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"></path></svg></button>{{end}}{{end}}
<div class="pki-certificate-detail">
  <dl class="pki-key-values pki-key-values--detail">
    <div class="pki-key-value"><dt>ID</dt><dd><code>{{.ID}}</code>{{template "detailCopy" .ID}}</dd></div>
    <div class="pki-key-value"><dt>Serial number</dt><dd><code>{{.SerialNumber}}</code>{{template "detailCopy" .SerialNumber}}</dd></div>
    <div class="pki-key-value"><dt>Subject CN</dt><dd><code>{{.SubjectCN}}</code>{{template "detailCopy" .SubjectCN}}</dd></div>
    <div class="pki-key-value"><dt>Subject organization</dt><dd><code>{{.SubjectOrg}}</code>{{template "detailCopy" .SubjectOrg}}</dd></div>
    <div class="pki-key-value"><dt>Tenant ID</dt><dd><code>{{.TenantID}}</code>{{template "detailCopy" .TenantID}}</dd></div>
    <div class="pki-key-value"><dt>Issuer CN</dt><dd><code>{{.IssuerCN}}</code>{{template "detailCopy" .IssuerCN}}</dd></div>
    <div class="pki-key-value pki-key-value--wide"><dt>SHA-256 fingerprint</dt><dd><code>{{.FingerprintSHA256}}</code>{{template "detailCopy" .FingerprintSHA256}}</dd></div>
    <div class="pki-key-value"><dt>Key algorithm</dt><dd><span>{{.KeyAlgorithm}}</span>{{template "detailCopy" .KeyAlgorithm}}</dd></div>
    <div class="pki-key-value"><dt>Purpose</dt><dd><span>{{.Purpose}}</span>{{template "detailCopy" .Purpose}}</dd></div>
    <div class="pki-key-value"><dt>Status</dt><dd><span class="badge {{.StatusClass}}">{{.Status}}</span>{{template "detailCopy" .Status}}</dd></div>
    <div class="pki-key-value"><dt>Not before</dt><dd><code>{{.NotBefore}}</code>{{template "detailCopy" .NotBefore}}</dd></div>
    <div class="pki-key-value"><dt>Not after</dt><dd><code>{{.NotAfter}}</code>{{template "detailCopy" .NotAfter}}</dd></div>
    <div class="pki-key-value"><dt>Issued at</dt><dd><code>{{.IssuedAt}}</code>{{template "detailCopy" .IssuedAt}}</dd></div>
    <div class="pki-key-value"><dt>Revoked at</dt><dd>{{if .RevokedAt}}<code>{{.RevokedAt}}</code>{{template "detailCopy" .RevokedAt}}{{else}}&mdash;{{end}}</dd></div>
    <div class="pki-key-value"><dt>Revocation reason</dt><dd>{{if .RevocationReason}}<span>{{.RevocationReason}}</span>{{template "detailCopy" .RevocationReason}}{{else}}&mdash;{{end}}</dd></div>
    <div class="pki-key-value"><dt>Parent CA ID</dt><dd>{{if .ParentCAID}}<code>{{.ParentCAID}}</code>{{template "detailCopy" .ParentCAID}}{{else}}&mdash;{{end}}</dd></div>
    <div class="pki-key-value"><dt>Agent code</dt><dd>{{if .AgentCode}}<code>{{.AgentCode}}</code>{{template "detailCopy" .AgentCode}}{{else}}&mdash;{{end}}</dd></div>
    <div class="pki-key-value"><dt>Sync version</dt><dd>{{if .SyncVersion}}<code>{{.SyncVersion}}</code>{{template "detailCopy" .SyncVersion}}{{else}}<span class="muted small">not returned by this PKI version</span>{{end}}</dd></div>
  </dl>
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
{{define "inventoryCopy"}}{{if .}}<button type="button" class="pki-copy-button" data-copy="{{.}}" onclick="copyPKIValue(this)" title="Copy value" aria-label="Copy value to clipboard"><svg class="pki-copy-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8h11v11H8z"></path><path d="M5 16H4V5h11v1"></path></svg><svg class="pki-copy-check" viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"></path></svg></button>{{end}}{{end}}
{{if .CertificatesError}}
  <div class="pki-certificate-notice" data-kind="{{if .CertificatesSignInRequired}}auth{{else}}pki{{end}}">
    <strong>{{if .CertificatesSignInRequired}}Sign in required{{else}}PKI unavailable{{end}}:</strong>
    <span>{{.CertificatesError}}</span>
    {{if .CertificatesSignInRequired}}<a class="btn btn-ghost" href="/kite-login?dashboard=%2Fobservability">Sign in &rarr;</a>{{end}}
  </div>
{{else if .HasCertificates}}
  <p class="muted small">Showing this computer's most recently issued active certificate. Select <strong>Full details</strong> for every <code>pki_certificates</code> field, certificate PEM and CSR.</p>
  {{range .Certificates}}
  <dl class="pki-key-values">
    <div class="pki-key-value"><dt>Agent code</dt><dd><code>{{.AgentCode}}</code>{{template "inventoryCopy" .AgentCode}}</dd></div>
    <div class="pki-key-value"><dt>Subject CN</dt><dd><code>{{.SubjectCN}}</code>{{template "inventoryCopy" .SubjectCN}}</dd></div>
    <div class="pki-key-value"><dt>Status</dt><dd><span class="badge {{.StatusClass}}">{{.Status}}</span>{{template "inventoryCopy" .Status}}</dd></div>
    <div class="pki-key-value"><dt>Serial number</dt><dd><code>{{.SerialNumber}}</code>{{template "inventoryCopy" .SerialNumber}}</dd></div>
    <div class="pki-key-value"><dt>Tenant ID</dt><dd><code>{{.TenantID}}</code>{{template "inventoryCopy" .TenantID}}</dd></div>
    <div class="pki-key-value"><dt>Issued at</dt><dd><code>{{.IssuedAt}}</code>{{template "inventoryCopy" .IssuedAt}}</dd></div>
    <div class="pki-key-value"><dt>Expires at</dt><dd><code>{{.NotAfter}}</code>{{template "inventoryCopy" .NotAfter}}</dd></div>
    <div class="pki-key-value"><dt>Purpose</dt><dd><span>{{.Purpose}}</span>{{template "inventoryCopy" .Purpose}}</dd></div>
    <div class="pki-key-value"><dt>Key algorithm</dt><dd><span>{{.KeyAlgorithm}}</span>{{template "inventoryCopy" .KeyAlgorithm}}</dd></div>
    <div class="pki-key-value pki-key-value--wide"><dt>SHA-256 fingerprint</dt><dd><code>{{.FingerprintSHA256}}</code>{{template "inventoryCopy" .FingerprintSHA256}}</dd></div>
  </dl>
  <div class="pki-certificate-actions">
    <button class="btn btn-ghost" type="button"
            hx-get="/fragments/observability/certificates/{{.ID}}"
            hx-target="#certificate-detail-{{.ID}}"
            hx-swap="innerHTML">Full details</button>
  </div>
  <div id="certificate-detail-{{.ID}}"></div>
  {{end}}
{{else}}
  <p class="muted">No PKI certificates have been issued for this organization yet. Certificates from individual and mass enrollments will appear here.</p>
{{end}}
<script>
window.copyPKIValue = function(button) {
  var value = button.getAttribute('data-copy') || '';
  if (!value) return;
  var copied = function() {
    button.classList.add('is-copied');
    button.setAttribute('aria-label', 'Copied');
    window.setTimeout(function() {
      button.classList.remove('is-copied');
      button.setAttribute('aria-label', 'Copy value to clipboard');
    }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(copied);
    return;
  }
  var input = document.createElement('textarea');
  input.value = value;
  input.style.position = 'fixed';
  input.style.opacity = '0';
  document.body.appendChild(input);
  input.select();
  if (document.execCommand('copy')) copied();
  input.remove();
};
</script>`))
