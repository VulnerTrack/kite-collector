package resource

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	"github.com/google/uuid"
)

// UserFromCertFile returns the identity of the user who enrolled this agent,
// as bound into the agent's own client certificate at enrollment: the Subject
// OrganizationalUnit carries the Supabase user UUID and an rfc822 SAN carries
// the user's email. Both are stamped server-side by PKI from the verified
// operator session (never from the CSR), so — like the tenant Organization —
// they are values the agent can log but not choose.
//
// The returned email is PII: never write it to a log or an OTel attribute.
// Log HashEmail(email) instead — see docs/observability.md. The user UUID is
// pseudonymous and may be logged as-is, like tenant.id.
//
// Returns ("", "") when the file is missing/unparseable, the certificate
// predates user stamping, or the OU is not a well-formed UUID.
func UserFromCertFile(certPath string) (userID, email string) {
	if strings.TrimSpace(certPath) == "" {
		return "", ""
	}
	pemBytes, err := os.ReadFile(certPath) //#nosec G304 -- operator-configured cert path
	if err != nil {
		return "", ""
	}
	return UserFromCertPEM(pemBytes)
}

// UserFromCertPEM extracts (userID, email) from PEM-encoded certificate
// material, reading the first leaf certificate in the bundle.
func UserFromCertPEM(pemBytes []byte) (userID, email string) {
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
		for _, ou := range cert.Subject.OrganizationalUnit {
			if u, perr := uuid.Parse(strings.TrimSpace(ou)); perr == nil {
				userID = u.String()
				break
			}
		}
		if len(cert.EmailAddresses) > 0 {
			email = cert.EmailAddresses[0]
		}
		// First leaf certificate wins; do not fall through to CA certs.
		return userID, email
	}
}

// HashEmail returns the SHA-256 hex digest of an email address, or "" for a
// blank one. This is what belongs in logs: an address is PII and both
// docs/observability.md and the guidelines.md PR checklist forbid logging PII
// in the clear, while a stable digest still correlates every line belonging to
// the same enrolling user. The address is lowercased and trimmed first so the
// same mailbox always yields the same digest.
//
// The digest is a pseudonym, not anonymization — the space of email addresses
// is enumerable, so anyone holding a candidate address can confirm it against
// a digest. It keeps addresses out of log storage; it does not remove the need
// to control access to the logs themselves.
func HashEmail(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
