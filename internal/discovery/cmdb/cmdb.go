// Package cmdb provides discovery sources for Configuration Management
// Database (CMDB) systems. Each source implements [discovery.Source] and
// enumerates configuration items / devices as [model.Asset] values.
// Assets imported from a CMDB are considered authorised by default since
// their presence in the CMDB implies organisational awareness.
//
// Every connector in this package is built on
// [github.com/vulnertrack/kite-collector/internal/discovery/connectorkit]:
// the enabled gate is honoured before any network call (F3), credentials are
// zeroed after the discovery call (R1), outbound clients are SSRF/TLS
// validated via connectorkit.SafeClient (unless the unexported baseURL test
// override is set), and each pagination loop is bounded by a
// connectorkit.NewGuard.
package cmdb

import "time"

const (
	// maxResponseBody bounds every CMDB connector's per-response read so a
	// malicious or misconfigured upstream cannot stream an unbounded body
	// into memory.
	maxResponseBody = 10 << 20 // 10 MiB

	// cmdbClientTimeout bounds every outbound request when a connector builds
	// its own plain client for the baseURL test override. Production clients
	// arrive pre-configured (with this same timeout) from
	// connectorkit.SafeClient.
	cmdbClientTimeout = 30 * time.Second
)

// truncateBytes returns at most maxLen bytes from data as a string.
func truncateBytes(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}
