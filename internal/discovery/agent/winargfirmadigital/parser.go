package winargfirmadigital

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

// CertFields captures the cert metadata the audit pipeline cares
// about.
type CertFields struct {
	ValidFrom    time.Time
	ValidTo      time.Time
	SubjectCN    string
	SubjectDN    string
	IssuerDN     string
	IsSelfSigned bool
	IsCA         bool
}

// ParseCertPEM parses a PEM-encoded cert body. Returns ok=false
// when no CERTIFICATE block is present.
func ParseCertPEM(body []byte) (CertFields, bool) {
	var out CertFields
	if len(body) == 0 {
		return out, false
	}
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.Contains(strings.ToUpper(block.Type), "CERTIFICATE") {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out.SubjectCN = cert.Subject.CommonName
		out.SubjectDN = cert.Subject.String()
		out.IssuerDN = cert.Issuer.String()
		out.ValidFrom = cert.NotBefore
		out.ValidTo = cert.NotAfter
		out.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()
		out.IsCA = cert.IsCA
		// First valid certificate wins (typical leaf-first PEM).
		return out, true
	}
	return out, false
}

// ParseCertDER parses a DER-encoded cert body.
func ParseCertDER(body []byte) (CertFields, bool) {
	var out CertFields
	if len(body) == 0 {
		return out, false
	}
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return out, false
	}
	out.SubjectCN = cert.Subject.CommonName
	out.SubjectDN = cert.Subject.String()
	out.IssuerDN = cert.Issuer.String()
	out.ValidFrom = cert.NotBefore
	out.ValidTo = cert.NotAfter
	out.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()
	out.IsCA = cert.IsCA
	return out, true
}

// SubjectSerialNumberFromDN extracts the serialNumber RDN
// from a Subject DN string. AFIP / ONTI commonly populate it
// with `CUIT NN-NNNNNNNN-N` or `CUIL NN-NNNNNNNN-N`.
func SubjectSerialNumberFromDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(p), "SERIALNUMBER=") {
			return strings.TrimSpace(p[len("SERIALNUMBER="):])
		}
	}
	return ""
}
