package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// webFPConfig tunes the in-scan web fingerprinter.
type webFPConfig struct {
	// VHosts are operator-supplied virtual-host names to try as SNI/Host
	// when a raw-IP probe is refused by a name-based reverse proxy.
	VHosts []string
	// IncludeAPI enables the API surface, which fans out to ~330
	// well-known endpoint probes (/openapi.json, /docs, /actuator/*,
	// /graphql, …) per web port. High signal but the heaviest surface,
	// so it is opt-in: the always-on default sweep uses only the cheap
	// header/JS/TLS surfaces, which already name the web server, the
	// framework (via cookies), and JS libraries in one request each.
	IncludeAPI bool
	// IncludeFile enables the file surface (60+ well-known path probes,
	// e.g. /swagger-ui/, /.env). Off by default — it is the slowest
	// surface — but it is where exact framework versions often leak.
	IncludeFile bool
	// VersionDisclosure probes exposed dependency manifests (composer.lock,
	// package-lock.json, …) on a reachable endpoint and parses the exact
	// versions into software (turning "Laravel" into "laravel/framework
	// 11.9.2"). A handful of harmless GETs; on by default.
	VersionDisclosure bool
	// Timeout bounds each per-mechanism probe.
	Timeout time.Duration
}

// maxVHostCandidates caps how many vhost names one gated port is retried
// with, so a long operator list or a fat PTR record cannot fan a single
// host out into an unbounded probe storm.
const maxVHostCandidates = 3

// recognizeWebSoftware sweeps every open web port of one host with the
// composite fingerprinter (TLS + headers + JS + API, optionally files) and
// returns the software it named plus a signal map describing ports that are
// TLS-open but name-gated (P2.4). When a raw-IP HTTPS probe is refused for
// an unrecognised SNI, it retries with vhost candidates — operator list,
// reverse-DNS PTR, cert SANs — each pinned to the in-scope IP so the sweep
// never leaves scan scope (P2.5).
func recognizeWebSoftware(ctx context.Context, ip netip.Addr, open []int, cfg webFPConfig) ([]model.InstalledSoftware, map[string]any) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = compositefingerprint.DefaultPerMechanismTimeout
	}

	var software []model.InstalledSoftware
	signals := map[string]any{}

	for _, port := range open {
		if ctx.Err() != nil {
			break
		}
		web, https := isWebPort(port)
		if !web {
			continue
		}
		scheme := "http"
		if https {
			scheme = "https"
		}

		// First pass: probe the raw IP. A pinned client lets the HTTP
		// surfaces tolerate a self-signed default cert and dial exactly
		// this IP; the composite TLS surface dials the IP directly and
		// captures an unrecognised-name refusal.
		firstClient := pinnedDialClient(ip, port, "", timeout)
		scanner := compositefingerprint.NewScannerWithClient(firstClient)
		res, err := scanner.Scan(ctx, scheme, ip.String(), port, compositefingerprint.Options{
			PerMechanismTimeout: timeout,
			DisableFile:         !cfg.IncludeFile,
			DisableAPI:          !cfg.IncludeAPI,
			InsecureSkipVerify:  true,
		})
		if err == nil {
			if sw := webSoftwareFromResult(res); len(sw) > 0 {
				software = append(software, sw...)
				if cfg.VersionDisclosure {
					software = append(software, probeVersionDisclosure(ctx, firstClient, scheme, ip.String(), port, timeout)...)
				}
				continue
			}
		}

		if !https {
			// Plain-HTTP endpoint with no framework signature: an exposed
			// dependency manifest can still name exact versions.
			if cfg.VersionDisclosure && err == nil {
				software = append(software, probeVersionDisclosure(ctx, firstClient, "http", ip.String(), port, timeout)...)
			}
			continue
		}

		// Name-based vhost retry. Only worth doing over TLS, where SNI
		// selects the server block.
		candidates := vhostCandidates(ctx, ip, cfg.VHosts, res)
		matched := false
		for _, name := range candidates {
			if ctx.Err() != nil {
				break
			}
			client := pinnedDialClient(ip, port, name, timeout)
			retryScanner := compositefingerprint.NewScannerWithClient(client)
			r2, rErr := retryScanner.Scan(ctx, "https", name, port, compositefingerprint.Options{
				PerMechanismTimeout: timeout,
				DisableFile:         !cfg.IncludeFile,
				DisableAPI:          !cfg.IncludeAPI,
				// TLS surface dials the name (public DNS), which would
				// leave scan scope; the pinned client already presents
				// the SNI on the in-scope IP for the HTTP surfaces, so
				// the dedicated TLS probe is disabled on retry.
				DisableTLS:         true,
				InsecureSkipVerify: true,
			})
			if rErr != nil {
				continue
			}
			if sw := webSoftwareFromResult(r2); len(sw) > 0 {
				software = append(software, sw...)
				if cfg.VersionDisclosure {
					software = append(software, probeVersionDisclosure(ctx, client, "https", name, port, timeout)...)
				}
				matched = true
				break
			}
		}

		// P2.4: a TLS-open port that yielded nothing because its SNI was
		// refused is not "no web here" — it is "web here, needs the right
		// vhost". Surface that instead of a silent zero.
		if !matched && tlsNameRejected(res) {
			signals[fmt.Sprintf("web_port_%d", port)] = map[string]any{
				"tls_open":         true,
				"sni_rejected":     true,
				"needs_vhost":      true,
				"candidates_tried": candidates,
			}
		}
	}

	return dedupeSoftware(software), signals
}

// vhostCandidates assembles, dedupes, and caps the virtual-host names to
// retry a gated port with: operator-configured names first (highest
// signal), then the IP's reverse-DNS PTR, then any SANs a default cert
// exposed. Wildcards and empties are dropped.
func vhostCandidates(ctx context.Context, ip netip.Addr, configured []string, res compositefingerprint.CompositeResult) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(strings.TrimSuffix(name, "."))
		if name == "" || strings.HasPrefix(name, "*") || strings.Contains(name, "/") {
			return
		}
		key := strings.ToLower(name)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, name)
	}

	for _, name := range configured {
		add(name)
	}

	// Reverse DNS — one bounded lookup. Best-effort; PTR is frequently
	// absent on tailnets and cloud IPs.
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip.String()); err == nil {
		for _, name := range names {
			add(name)
		}
	}

	// Cert SANs, when a default cert was presented before any refusal.
	if res.TLS != nil {
		for _, san := range res.TLS.Cert.SANs {
			add(san)
		}
	}

	if len(out) > maxVHostCandidates {
		out = out[:maxVHostCandidates]
	}
	return out
}

// dedupeSoftware collapses rows that share (name, version, package
// manager, install path) so a product named by two surfaces or two ports
// does not double up. Order is stabilised by name then version.
func dedupeSoftware(in []model.InstalledSoftware) []model.InstalledSoftware {
	if len(in) <= 1 {
		return in
	}
	seen := map[string]bool{}
	out := in[:0:0]
	for _, sw := range in {
		key := strings.ToLower(strings.Join([]string{
			sw.SoftwareName, sw.Version, sw.PackageManager, sw.InstallPath,
		}, "\x1f"))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sw)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SoftwareName != out[j].SoftwareName {
			return out[i].SoftwareName < out[j].SoftwareName
		}
		return out[i].Version < out[j].Version
	})
	return out
}
