// Package tlsfingerprint identifies the hosting / CDN / managed-platform
// vendor behind a TLS endpoint by reading the peer certificate chain
// and matching the Subject CN, Subject Alternative Names, and issuer
// against a curated catalog.
//
// This is the transport-layer complement to apifingerprint (HTTP REST
// probes) and jsfingerprint (HTML/JS body scans). It works before any
// application-layer handshake: even a host that returns 404 on every
// HTTP path will leak its hosting provider through the cert.
//
// On JA3 / JA4 / JA4S / JA5:
//
//   - JA3 is a 32-char MD5 over the ClientHello (TLS version, ciphers,
//     extensions, supported_groups, ec_point_formats). It identifies
//     the *client*. Go's crypto/tls produces a stable JA3, so every
//     kite-collector run emits the same one — operators can compute it
//     once via ClientJA3String() and pin it in their detection rules.
//   - JA3S is the server-side analogue (ServerHello). Go's crypto/tls
//     does not expose the raw ServerHello bytes, so a faithful JA3S
//     capture requires a custom dialer that intercepts the handshake
//     at the byte level. Out of scope for this initial package; the
//     Result struct reserves the field so a future implementation
//     drops in cleanly.
//   - JA4 / JA4S are FoxIO's modern reformulation (longer, more
//     features). Same Go-runtime constraint as JA3S — reserved field.
//   - JA5 (Salesforce) is behavioural — observed handshake count,
//     timing, mTLS reuse — and only makes sense from the *server's*
//     vantage point. Not applicable to a client-side scanner.
//
// Read-only by intent: the package opens TLS connections, reads
// metadata, then closes — no application data is exchanged, no auth
// is attempted.
package tlsfingerprint

import (
	"crypto/x509"
	"regexp"
	"sort"
	"strings"
)

// Category groups TLS fingerprints by the kind of vendor identified.
type Category string

const (
	CategoryBaaS         Category = "baas"
	CategoryCDN          Category = "cdn"
	CategoryHosting      Category = "hosting"
	CategoryServerless   Category = "serverless"
	CategoryStaticHost   Category = "static-host"
	CategoryAuth         Category = "auth"
	CategoryCloudCompute Category = "cloud-compute"
	CategoryStorage      Category = "storage"
	CategoryGeneric      Category = "generic"
)

// Confidence ranks how certain a TLS fingerprint match is.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// SignalKind classifies which cert field produced the hit.
type SignalKind string

const (
	SignalSANSuffix   SignalKind = "san-suffix"
	SignalIssuerName  SignalKind = "issuer-name"
	SignalSubjectCN   SignalKind = "subject-cn"
	SignalOCSPHost    SignalKind = "ocsp-host"
	SignalCertExtra   SignalKind = "cert-extra"
)

// Pattern is one matcher in a Signature. Exactly one of SANSuffix /
// IssuerRegex / SubjectRegex / OCSPHost must be set.
type Pattern struct {
	Name string
	// SANSuffix matches when any SAN ends with this string. Includes
	// the leading dot ("." for "*.supabase.co"). Case-insensitive.
	SANSuffix string
	// IssuerRegex matches Cert.Issuer.CommonName or
	// Cert.Issuer.Organization joined with " — ".
	IssuerRegex *regexp.Regexp
	// SubjectRegex matches Cert.Subject.CommonName.
	SubjectRegex *regexp.Regexp
	// OCSPHost matches OCSP responder URL host.
	OCSPHost string
	Kind       SignalKind
	Confidence Confidence
}

// Signature is one vendor's detection rule set. Any Pattern matching
// emits a Fingerprint; multiple matches stack into Evidence.
type Signature struct {
	Vendor   string
	Product  string
	Category Category
	Patterns []Pattern
}

// CertSummary is the read-only metadata extracted from the peer cert
// chain. The Detector populates this once per Scan; vendor matching
// runs against it.
type CertSummary struct {
	SubjectCN    string    `json:"subject_cn"`
	SubjectOrg   []string  `json:"subject_org,omitempty"`
	SANs         []string  `json:"sans"`
	IssuerCN     string    `json:"issuer_cn"`
	IssuerOrg    []string  `json:"issuer_org,omitempty"`
	IssuerJoined string    `json:"issuer_joined"`
	NotBefore    string    `json:"not_before"`
	NotAfter     string    `json:"not_after"`
	SignatureAlg string    `json:"signature_alg"`
	PublicKeyAlg string    `json:"public_key_alg"`
	OCSPServers  []string  `json:"ocsp_servers,omitempty"`
	CRLPoints    []string  `json:"crl_points,omitempty"`
}

// Fingerprint is one matched vendor on one TLS endpoint.
type Fingerprint struct {
	Vendor     string     `json:"vendor"`
	Product    string     `json:"product"`
	Category   Category   `json:"category"`
	Endpoint   string     `json:"endpoint"`
	Evidence   []string   `json:"evidence"`
	Confidence Confidence `json:"confidence"`
}

// Result is the full output of one Scan() call. Cert metadata is
// always returned even when no vendor signature matches — operators
// still get the SAN list / issuer for inventory.
type Result struct {
	Endpoint     string        `json:"endpoint"`
	Cert         CertSummary   `json:"cert"`
	Fingerprints []Fingerprint `json:"fingerprints"`
	// ClientJA3 holds the JA3 string of the *kite-collector* end of
	// the handshake. Populated by the scanner so operators can pin
	// expected outgoing fingerprints without re-deriving them.
	ClientJA3 string `json:"client_ja3,omitempty"`
	// ServerJA3S, ServerJA4S are reserved for a future faithful-
	// handshake capture; current scanner leaves them empty.
	ServerJA3S string `json:"server_ja3s,omitempty"`
	ServerJA4S string `json:"server_ja4s,omitempty"`
}

// SummariseCert converts an *x509.Certificate into the read-only
// metadata shape Signatures match against. Exposes both the issuer
// CN and a joined "CN — O1, O2" string so issuer regex patterns can
// match either form.
func SummariseCert(c *x509.Certificate) CertSummary {
	if c == nil {
		return CertSummary{}
	}
	cs := CertSummary{
		SubjectCN:    c.Subject.CommonName,
		SubjectOrg:   append([]string{}, c.Subject.Organization...),
		IssuerCN:     c.Issuer.CommonName,
		IssuerOrg:    append([]string{}, c.Issuer.Organization...),
		NotBefore:    c.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:     c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		SignatureAlg: c.SignatureAlgorithm.String(),
		PublicKeyAlg: c.PublicKeyAlgorithm.String(),
		OCSPServers:  append([]string{}, c.OCSPServer...),
	}
	// Merge all SAN sources — DNS names, IP addresses, URIs.
	cs.SANs = append(cs.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		cs.SANs = append(cs.SANs, ip.String())
	}
	for _, u := range c.URIs {
		cs.SANs = append(cs.SANs, u.String())
	}
	sort.Strings(cs.SANs)
	for _, dp := range c.CRLDistributionPoints {
		cs.CRLPoints = append(cs.CRLPoints, dp)
	}
	// Build issuer joined form for regex matchers.
	parts := []string{cs.IssuerCN}
	if len(cs.IssuerOrg) > 0 {
		parts = append(parts, strings.Join(cs.IssuerOrg, ", "))
	}
	cs.IssuerJoined = strings.Join(parts, " — ")
	return cs
}

// MatchPattern reports whether p matches the supplied cert summary.
// Returns (matched, evidence). Evidence is a short human-readable
// description suitable for the Fingerprint.Evidence slice.
func MatchPattern(p Pattern, cs CertSummary) (bool, string) {
	switch {
	case p.SANSuffix != "":
		want := strings.ToLower(p.SANSuffix)
		for _, s := range cs.SANs {
			lower := strings.ToLower(s)
			if strings.HasSuffix(lower, want) {
				return true, "san-suffix:" + p.Name + " — " + s
			}
		}
	case p.IssuerRegex != nil:
		if p.IssuerRegex.MatchString(cs.IssuerJoined) {
			return true, "issuer:" + p.Name + " — " + cs.IssuerJoined
		}
	case p.SubjectRegex != nil:
		if p.SubjectRegex.MatchString(cs.SubjectCN) {
			return true, "subject:" + p.Name + " — " + cs.SubjectCN
		}
	case p.OCSPHost != "":
		want := strings.ToLower(p.OCSPHost)
		for _, srv := range cs.OCSPServers {
			if strings.Contains(strings.ToLower(srv), want) {
				return true, "ocsp:" + p.Name + " — " + srv
			}
		}
	}
	return false, ""
}

// SortFingerprints orders fingerprints by vendor, product.
func SortFingerprints(fps []Fingerprint) {
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Vendor != fps[j].Vendor {
			return fps[i].Vendor < fps[j].Vendor
		}
		return fps[i].Product < fps[j].Product
	})
}

// confRank converts a Confidence to an integer for comparison.
func confRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

func stronger(a, b Confidence) Confidence {
	if confRank(a) >= confRank(b) {
		return a
	}
	return b
}

// uniqueStrings — same helper shape as the sibling packages.
func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
