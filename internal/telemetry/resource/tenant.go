package resource

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	"github.com/google/uuid"
)

// TenantFromCertFile returns the tenant UUID bound into the agent's own client
// certificate — the Subject Organization field PKI stamps at enrollment
// (RFC-0063 §5.1) — or "" when the file is missing/unparseable or its
// Organization is not a well-formed UUID.
//
// Authority note (RFC-0150): the *certificate* is the authoritative tenant
// source, but that authority is now enforced SERVER-SIDE at the collector,
// which overwrites the OTLP tenant.id resource attribute from the same cert
// Organization (read via the mTLS peer or a Cloudflare-forwarded header). The
// value produced here is therefore a non-load-bearing HINT: it seeds tenant.id
// so the attribute is populated for the agent's own local visibility and for
// any path the collector does not overwrite, but it can never be trusted over
// the collector's determination. Because both sides read the same cert, the
// values agree; the agent cannot assert a tenant the collector would disagree
// with.
func TenantFromCertFile(certPath string) string {
	id, _ := TenantOrgFromCertFile(certPath)
	return id
}

// TenantOrgFromCertFile returns both tenant identifiers PKI can stamp
// into the Subject Organization at enrollment: the tenant UUID (RFC-0063
// §5.1) and, when the PKI includes one, the human-readable organization
// name carried as an additional non-UUID Organization value (multi-valued
// O is standard X.509). Either half is "" when absent — certificates
// issued before org-name stamping carry only the UUID, and both are ""
// when the file is missing or unparseable.
//
// Same authority note as TenantFromCertFile: display/log material, never
// load-bearing — the collector re-derives tenancy from the presented
// certificate server-side.
func TenantOrgFromCertFile(certPath string) (tenantID, orgName string) {
	if strings.TrimSpace(certPath) == "" {
		return "", ""
	}
	pemBytes, err := os.ReadFile(certPath) //#nosec G304 -- operator-configured cert path
	if err != nil {
		return "", ""
	}
	return tenantOrgFromCertPEM(pemBytes)
}

func tenantOrgFromCertPEM(pemBytes []byte) (tenantID, orgName string) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return "", ""
		}
		pemBytes = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		for _, org := range cert.Subject.Organization {
			org = strings.TrimSpace(org)
			if org == "" {
				continue
			}
			if t, perr := uuid.Parse(org); perr == nil {
				if tenantID == "" {
					tenantID = t.String()
				}
				continue
			}
			if orgName == "" {
				orgName = org
			}
		}
		// First leaf certificate wins; do not fall through to CA certs.
		return tenantID, orgName
	}
}

// ResolveTenantID returns the agent's tenant, preferring the value bound into
// its client certificate over the KITE_TENANT_ID environment variable. The env
// var remains a fallback for pre-enrollment / non-mTLS setups.
//
// Post-RFC-0150 this seeds a HINT only: the collector re-derives the tenant
// from the presented certificate and overwrites tenant.id server-side, so a
// stale KITE_TENANT_ID cannot cause a mis-tenanted asset — at worst it stamps a
// hint the collector replaces (or clears, under stamp_empty).
func ResolveTenantID(certPath, envTenant string) string {
	if t := TenantFromCertFile(certPath); t != "" {
		return t
	}
	return strings.TrimSpace(envTenant)
}
