package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// PackageManager tags stamped on network-recognised software so the
// dashboard and downstream CVE matching can tell how a row was learned:
// a service-banner handshake versus an HTTP stack fingerprint.
const (
	pkgMgrNetworkService     = "network_service"
	pkgMgrNetworkFingerprint = "network_fingerprint"
)

// webPorts are the TCP ports the in-scan web fingerprinter treats as
// HTTP(S). https* ports probe over TLS; the rest over plain HTTP.
var (
	httpsPorts = map[int]bool{443: true, 8443: true, 4443: true, 9443: true, 8843: true}
	httpPorts  = map[int]bool{80: true, 8080: true, 8000: true, 8888: true, 3000: true}
)

// isWebPort reports whether a port should be swept by the composite web
// fingerprinter and, when so, whether it speaks TLS.
func isWebPort(port int) (web, https bool) {
	if httpsPorts[port] {
		return true, true
	}
	if httpPorts[port] {
		return true, false
	}
	return false, false
}

// serviceProduct maps a fingerprintx protocol id to a human product name
// and vendor for the software inventory. Unmapped protocols fall back to
// the protocol id itself as the product name with an empty vendor.
func serviceProduct(protocol string) (product, vendor string) {
	switch strings.ToLower(protocol) {
	case "mysql":
		return "MySQL", "Oracle"
	case "mariadb":
		return "MariaDB", "MariaDB Foundation"
	case "postgresql":
		return "PostgreSQL", "PostgreSQL Global Development Group"
	case "redis":
		return "Redis", "Redis"
	case "mongodb":
		return "MongoDB", "MongoDB"
	case "mssql":
		return "Microsoft SQL Server", "Microsoft"
	case "ssh":
		return "OpenSSH", "OpenBSD"
	case "rdp":
		return "Remote Desktop Protocol", "Microsoft"
	case "smb":
		return "SMB", ""
	case "ldap":
		return "LDAP", ""
	case "ftp":
		return "FTP", ""
	case "telnet":
		return "Telnet", ""
	case "vnc":
		return "VNC", ""
	case "rabbitmq", "amqp":
		return "RabbitMQ", "VMware"
	case "elasticsearch":
		return "Elasticsearch", "Elastic"
	case "memcached":
		return "Memcached", ""
	case "kafka":
		return "Apache Kafka", "Apache Software Foundation"
	default:
		return protocol, ""
	}
}

// serviceSoftware turns per-port service fingerprints (protocol + version,
// straight from the handshake banner) into installed-software rows. This is
// the "banner → product+version" recognition: MySQL 8.4.3, Redis 7.2, the
// SSH build — data the scanner already reads on the wire but historically
// only stashed in a tag. The web protocols (http/https) are skipped here
// because the composite fingerprinter names their stack far more richly.
func serviceSoftware(services map[int]servicefp.Result) []model.InstalledSoftware {
	if len(services) == 0 {
		return nil
	}
	ports := make([]int, 0, len(services))
	for p := range services {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	out := make([]model.InstalledSoftware, 0, len(ports))
	for _, port := range ports {
		res := services[port]
		proto := strings.ToLower(res.Protocol)
		if proto == "" || proto == "http" || proto == "https" {
			continue
		}
		product, vendor := serviceProduct(res.Protocol)
		out = append(out, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   product,
			Vendor:         vendor,
			Version:        cleanVersion(res.Version),
			PackageManager: pkgMgrNetworkService,
			// InstallPath keeps otherwise-identical (name, version) rows
			// distinct per listening port, and records where the service
			// was observed.
			InstallPath: fmt.Sprintf("tcp/%d", port),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// versionToken matches a dotted numeric version embedded in evidence
// strings (e.g. a CDN URL "bootstrap/3.4.1/…" or a header value). It is
// deliberately conservative: at least major.minor, optional patch/suffix.
var versionToken = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z]+)?)\b`)

// cleanVersion trims and bounds a raw version banner so a noisy handshake
// string cannot bloat an inventory row.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

// extractVersion pulls the first plausible version token out of a
// fingerprint's evidence lines. Returns "" when none is present — most web
// signals carry no version, and a wrong version is worse than none.
func extractVersion(evidence []string) string {
	for _, e := range evidence {
		if m := versionToken.FindString(e); m != "" {
			return m
		}
	}
	return ""
}

// webSoftwareFromResult flattens a composite fingerprint into installed-
// software rows, one per (vendor, product) pick, deduplicated across the
// TLS / header / JS / API surfaces and keeping the strongest confidence.
// Versions are lifted from evidence when a surface exposed one (P2.6).
func webSoftwareFromResult(res compositefingerprint.CompositeResult) []model.InstalledSoftware {
	type agg struct {
		vendor, product, version string
		conf                     int
	}
	seen := map[string]*agg{}
	consider := func(vendor, product string, evidence []string, conf string) {
		product = strings.TrimSpace(product)
		vendor = strings.TrimSpace(vendor)
		if product == "" {
			product = vendor
		}
		if product == "" {
			return
		}
		key := strings.ToLower(vendor + "|" + product)
		a := seen[key]
		if a == nil {
			a = &agg{vendor: vendor, product: product}
			seen[key] = a
		}
		if r := confRank(conf); r > a.conf {
			a.conf = r
		}
		if a.version == "" {
			a.version = extractVersion(evidence)
		}
	}

	if res.TLS != nil {
		for _, fp := range res.TLS.Fingerprints {
			consider(fp.Vendor, fp.Product, fp.Evidence, string(fp.Confidence))
		}
	}
	if res.Header != nil {
		for _, fp := range res.Header.Fingerprints {
			consider(fp.Vendor, fp.Product, fp.Evidence, string(fp.Confidence))
		}
	}
	if res.JS != nil {
		for _, fp := range res.JS.Fingerprints {
			consider(fp.Vendor, fp.Product, fp.Evidence, string(fp.Confidence))
		}
	}
	if res.API != nil {
		for _, fp := range res.API.Fingerprints {
			consider(fp.Vendor, fp.Product, fp.Evidence, string(fp.Confidence))
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]model.InstalledSoftware, 0, len(keys))
	for _, k := range keys {
		a := seen[k]
		out = append(out, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   a.product,
			Vendor:         a.vendor,
			Version:        a.version,
			PackageManager: pkgMgrNetworkFingerprint,
			InstallPath:    res.Endpoint,
		})
	}
	return out
}

// confRank scores a string confidence band for comparison. Mirrors the
// composite consolidator so the two agree on ordering.
func confRank(c string) int {
	switch strings.ToLower(c) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// pinnedDialClient builds an http.Client whose every connection is dialled
// to a single ip:port regardless of the request's Host, while presenting
// the requested hostname for SNI and the Host header. This is the
// programmatic equivalent of `curl --resolve host:port:ip`: it lets the
// scanner fingerprint a name-based virtual host (e.g. shop.example) that a
// reverse proxy only serves under the right SNI, while still contacting the
// exact in-scope IP the scan is targeting (no scope escape).
func pinnedDialClient(ip netip.Addr, port int, sni string, timeout time.Duration) *http.Client {
	target := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // read-only stack fingerprint; cert trust is not the goal
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   2,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A fingerprint sweep reads the landing response, not a login
		// redirect chain; capping redirects keeps a misconfigured vhost
		// from bouncing the probe around.
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// tlsNameRejected reports whether a composite result failed because the
// server refused the presented SNI ("unrecognized name", TLS alert 112) —
// the signature of a name-based vhost reached by raw IP. This is the exact
// blind spot when scanning a tailnet (every host is an IP): the web layer
// silently yields zero. Detecting it lets the scanner both retry with vhost
// candidates and, failing that, surface an actionable signal.
func tlsNameRejected(res compositefingerprint.CompositeResult) bool {
	for _, e := range res.Errors {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "unrecognized name") ||
			strings.Contains(msg, "unrecognised name") {
			return true
		}
	}
	return false
}
