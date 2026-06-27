package winafipwsaa

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"regexp"
	"strings"
	"time"
)

// taDoc captures the WSAA Ticket-de-Acceso XML shape:
//
//	<loginTicketResponse version="1.0">
//	  <header>
//	    <source>CN=wsaa, O=AFIP, C=AR, SERIALNUMBER=CUIT 33...</source>
//	    <destination>SERIALNUMBER=CUIT 30...</destination>
//	    <generationTime>2026-06-23T08:00:00.000-03:00</generationTime>
//	    <expirationTime>2026-06-23T20:00:00.000-03:00</expirationTime>
//	  </header>
//	  <credentials><token>...</token><sign>...</sign></credentials>
//	</loginTicketResponse>
type taDoc struct {
	XMLName     xml.Name      `xml:"loginTicketResponse"`
	Header      taHeader      `xml:"header"`
	Credentials taCredentials `xml:"credentials"`
}

type taHeader struct {
	Source         string `xml:"source"`
	Destination    string `xml:"destination"`
	GenerationTime string `xml:"generationTime"`
	ExpirationTime string `xml:"expirationTime"`
}

type taCredentials struct {
	Token string `xml:"token"`
	Sign  string `xml:"sign"`
}

// cuitRE matches `CUIT XX-XXXXXXXX-X` (the AFIP serialNumber
// format) OR a bare 11-digit run. Hyphens optional.
var cuitRE = regexp.MustCompile(`(?i)CUIT\s*[: ]?\s*(\d{2})-?(\d{8})-?(\d)|(\d{11})`)

// CuitFingerprintFromText scans text for an AFIP CUIT and
// returns the entity-type prefix (2 chars) and last-4 digits.
// Empty input or non-match returns "","".
func CuitFingerprintFromText(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	if m[1] != "" {
		prefix = m[1]
		// suffix4 = last 4 digits of the 11-digit CUIT =
		// last 3 of the 8-digit middle + the check digit.
		mid := m[2]
		check := m[3]
		if len(mid) >= 3 {
			suffix4 = mid[len(mid)-3:] + check
		} else {
			suffix4 = mid + check
		}
	} else {
		bare := m[4]
		if len(bare) == 11 {
			prefix = bare[:2]
			suffix4 = bare[7:]
		}
	}
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// ParseTicketAcceso parses a TA XML body, returning the
// scalar fields the audit pipeline needs. Token presence is a
// boolean; the actual value is never returned. now() is
// injected for deterministic tests.
type TAFields struct {
	ExpiresAt      string
	SourceCuitPfx  string
	SourceCuitSfx4 string
	DestCuitPfx    string
	DestCuitSfx4   string
	IsTokenPresent bool
	IsExpired      bool
}

// ParseTicketAcceso returns TAFields plus an `ok` flag — false
// if the body did not parse as a TA XML.
func ParseTicketAcceso(body []byte, now time.Time) (TAFields, bool) {
	var out TAFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	var doc taDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return out, false
	}
	if doc.XMLName.Local != "loginTicketResponse" {
		return out, false
	}
	out.ExpiresAt = strings.TrimSpace(doc.Header.ExpirationTime)
	out.IsTokenPresent = strings.TrimSpace(doc.Credentials.Token) != ""
	if out.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, out.ExpiresAt); err == nil {
			out.IsExpired = t.Before(now)
		} else if t, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil {
			out.IsExpired = t.Before(now)
		}
	}
	out.SourceCuitPfx, out.SourceCuitSfx4 = CuitFingerprintFromText(doc.Header.Source)
	out.DestCuitPfx, out.DestCuitSfx4 = CuitFingerprintFromText(doc.Header.Destination)
	return out, true
}

// KeyAnalysis captures private-key file fields.
type KeyAnalysis struct {
	IsUnencrypted bool
}

// AnalyzePrivateKey decodes a PEM body and reports whether the
// key is unencrypted. RFC 1421 `Proc-Type: 4,ENCRYPTED` and
// PKCS#8 `ENCRYPTED PRIVATE KEY` headers both count as
// encrypted. A body without recognisable PEM is treated as
// not-a-private-key (returns ok=false).
func AnalyzePrivateKey(body []byte) (KeyAnalysis, bool) {
	var out KeyAnalysis
	if len(body) == 0 {
		return out, false
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return out, false
	}
	t := strings.ToUpper(block.Type)
	if !strings.Contains(t, "PRIVATE KEY") {
		return out, false
	}
	if strings.Contains(t, "ENCRYPTED") {
		return out, true
	}
	if v, ok := block.Headers["Proc-Type"]; ok && strings.Contains(strings.ToUpper(v), "ENCRYPTED") {
		return out, true
	}
	out.IsUnencrypted = true
	return out, true
}

// CertAnalysis captures the cert fields the audit pipeline
// inventories.
type CertAnalysis struct {
	SubjectCN        string
	CuitEntityPrefix string
	CuitSuffix4      string
}

// AnalyzeCert decodes a PEM body and parses the leaf cert,
// returning the SubjectCN + CUIT fingerprint extracted from
// the Subject (AFIP issues certs with `serialNumber=CUIT
// XX-XXXXXXXX-X` in the Subject DN). Returns ok=false if the
// body is not a cert.
func AnalyzeCert(body []byte) (CertAnalysis, bool) {
	var out CertAnalysis
	if len(body) == 0 {
		return out, false
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return out, false
	}
	if !strings.Contains(strings.ToUpper(block.Type), "CERTIFICATE") {
		return out, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return out, false
	}
	out.SubjectCN = cert.Subject.CommonName
	// AFIP encodes the CUIT in Subject's serialNumber field.
	out.CuitEntityPrefix, out.CuitSuffix4 = CuitFingerprintFromText(cert.Subject.SerialNumber)
	if out.CuitEntityPrefix == "" {
		out.CuitEntityPrefix, out.CuitSuffix4 = CuitFingerprintFromText(cert.Subject.String())
	}
	return out, true
}
