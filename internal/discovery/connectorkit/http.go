package connectorkit

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// clientTimeout bounds every connector's outbound request, matching the value
// the pre-existing hardened connectors (wazuh, proxmox, ...) use.
const clientTimeout = 30 * time.Second

// SafeClient validates rawURL via safenet.ValidateEndpoint, builds a TLS-aware
// *http.Client via safenet.TLSConfig, and returns both the client and the
// validated *url.URL. allowPrivate=true is passed only for connectors that are
// commonly self-hosted (SCCM, NetBox, Device42); SaaS-only connectors (Intune,
// Jamf, ServiceNow, Workspace ONE, Kandji, Lansweeper) pass false so an
// operator-supplied base URL resolving to a private or cloud-metadata address
// is rejected (SSRF, Finding F1).
//
// The TLS insecure/custom-CA escape hatches are namespaced per source via the
// KITE_<SOURCE>_INSECURE and KITE_<SOURCE>_CA_CERT env vars, matching the
// convention safenet.TLSConfig expects.
//
// SafeClient is a thin wrapper over SafeClientWithTimeout that supplies the
// shared 30s clientTimeout, so the ten existing MDM/CMDB consumers keep their
// current behavior unchanged.
func SafeClient(sourceName, rawURL string, allowPrivate bool) (*http.Client, *url.URL, error) {
	return SafeClientWithTimeout(sourceName, rawURL, allowPrivate, clientTimeout)
}

// SafeClientWithTimeout behaves exactly like SafeClient but bounds every
// outbound request with the caller-supplied timeout instead of the shared 30s
// default. Connectors that expose an operator-configurable request timeout
// (RFC-0137 R1: Entra's request_timeout_seconds, previously parsed-but-dead)
// call this so that value finally takes effect end-to-end. A non-positive
// timeout falls back to the default clientTimeout, so a misconfigured or unset
// value can never produce a client with no timeout (Finding F4).
func SafeClientWithTimeout(sourceName, rawURL string, allowPrivate bool, timeout time.Duration) (*http.Client, *url.URL, error) {
	if timeout <= 0 {
		timeout = clientTimeout
	}

	var opts []safenet.Option
	if allowPrivate {
		opts = append(opts, safenet.AllowPrivate())
	}
	u, err := safenet.ValidateEndpoint(rawURL, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sourceName, err)
	}

	upper := strings.ToUpper(sourceName)
	tlsCfg, err := safenet.TLSConfig(
		fmt.Sprintf("KITE_%s_INSECURE", upper),
		fmt.Sprintf("KITE_%s_CA_CERT", upper),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sourceName, err)
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return client, u, nil
}
