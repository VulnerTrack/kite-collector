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
// This is the authoritative source of the agent's tenant: it cannot diverge
// from the certificate the agent actually presents. It exists because the OTLP
// resource attribute tenant.id was previously read only from KITE_TENANT_ID,
// which is easy to leave unset — landing every asset with a NULL/"unknown"
// tenant even though the cert carried the real one.
func TenantFromCertFile(certPath string) string {
	if strings.TrimSpace(certPath) == "" {
		return ""
	}
	pemBytes, err := os.ReadFile(certPath) //#nosec G304 -- operator-configured cert path
	if err != nil {
		return ""
	}
	return tenantFromCertPEM(pemBytes)
}

func tenantFromCertPEM(pemBytes []byte) string {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return ""
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
			if t, perr := uuid.Parse(strings.TrimSpace(org)); perr == nil {
				return t.String()
			}
		}
		// First leaf certificate wins; do not fall through to CA certs.
		return ""
	}
}

// ResolveTenantID returns the agent's tenant, preferring the value bound into
// its client certificate over the KITE_TENANT_ID environment variable. The env
// var remains a fallback for pre-enrollment / non-mTLS setups, but a valid
// cert-derived tenant is authoritative and cannot be overridden by a stale env.
func ResolveTenantID(certPath, envTenant string) string {
	if t := TenantFromCertFile(certPath); t != "" {
		return t
	}
	return strings.TrimSpace(envTenant)
}
