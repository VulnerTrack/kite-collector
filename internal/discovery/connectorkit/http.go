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
func SafeClient(sourceName, rawURL string, allowPrivate bool) (*http.Client, *url.URL, error) {
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
		Timeout:   clientTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return client, u, nil
}
