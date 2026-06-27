package certificates

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //#nosec G505 -- SHA1 is for the legacy fingerprint column, not for new crypto
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// sha256Fingerprint returns the lowercase hex SHA-256 of cert.Raw. This
// is the natural key for host_certificates — multiple symlinks to the
// same cert collapse to one row.
func sha256Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// sha1Fingerprint returns the lowercase hex SHA-1 of cert.Raw. We
// retain it only as a legacy join key for older tooling (browsers'
// certutil, openssl x509 -fingerprint default). Never used for security
// decisions inside this package.
func sha1Fingerprint(raw []byte) string {
	sum := sha1.Sum(raw) //#nosec G401 -- legacy fingerprint, not cryptographic decision
	return hex.EncodeToString(sum[:])
}

// keyAlgorithmString returns a human-readable algorithm + size descriptor.
// Examples: "RSA-2048", "ECDSA-P256", "Ed25519", "DSA-1024", "unknown".
func keyAlgorithmString(c *x509.Certificate) string {
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pk.N.BitLen())
	case *ecdsa.PublicKey:
		curve := "unknown"
		if pk.Curve != nil && pk.Params() != nil {
			curve = pk.Curve.Params().Name
		}
		return "ECDSA-" + curve
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// keyUsageList converts the bitmask x509.KeyUsage into a sorted slice
// of stable, lowercase-hyphen tokens.
func keyUsageList(u x509.KeyUsage) []string {
	var out []string
	if u&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digital-signature")
	}
	if u&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "content-commitment")
	}
	if u&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "key-encipherment")
	}
	if u&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "data-encipherment")
	}
	if u&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "key-agreement")
	}
	if u&x509.KeyUsageCertSign != 0 {
		out = append(out, "cert-sign")
	}
	if u&x509.KeyUsageCRLSign != 0 {
		out = append(out, "crl-sign")
	}
	if u&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "encipher-only")
	}
	if u&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "decipher-only")
	}
	return out
}

// extKeyUsageList converts the slice of x509.ExtKeyUsage into stable
// tokens (e.g. "server-auth", "client-auth", "code-signing").
func extKeyUsageList(us []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		switch u {
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "server-auth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "client-auth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "code-signing")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "email-protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			out = append(out, "ipsec-end-system")
		case x509.ExtKeyUsageIPSECTunnel:
			out = append(out, "ipsec-tunnel")
		case x509.ExtKeyUsageIPSECUser:
			out = append(out, "ipsec-user")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "time-stamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "ocsp-signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			out = append(out, "microsoft-sgc")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			out = append(out, "netscape-sgc")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			out = append(out, "microsoft-commercial-code-signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			out = append(out, "microsoft-kernel-code-signing")
		default:
			out = append(out, fmt.Sprintf("unknown-%d", int(u)))
		}
	}
	return out
}

// ipStrings converts net.IP entries to canonical string form. Used for
// the san_ip JSON array column.
func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// isSelfSigned reports whether issuer == subject AND signature verifies
// against own public key. The cheap string compare alone catches most
// real-world cases; the verify catches edge cases where issuer DN was
// reused without actual self-signing (rare but possible).
func isSelfSigned(c *x509.Certificate) bool {
	if c.Issuer.String() != c.Subject.String() {
		return false
	}
	// Verify the signature with the cert's own key. Failure means the
	// matching DNs are coincidental, not actual self-signing.
	return c.CheckSignatureFrom(c) == nil
}

// JoinDN returns the components of an RDN sequence joined with ", " in
// canonical order. Helper for tests that want to compare against a known
// subject string without depending on Go's pkix.Name.String() format.
func JoinDN(parts ...string) string {
	return strings.Join(parts, ", ")
}
