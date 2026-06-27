package lldp

// LogCode — typed identifier for every structured log entry the
// lldp package emits. Convention: `lan_lldp.<surface>.<event>`.
// (The compound `lan_lldp` namespace keeps grep alignment with sibling
// lan/<protocol> packages while making cross-tenant log indexes
// unambiguous about which LAN protocol the event came from.)
type LogCode string

const (
	// neighbor-discovery surface — wraps lldpctl invocation
	LogCodeLLDPCtlMissing         LogCode = "lan_lldp.discover.lldpctl_missing"
	LogCodeLLDPCtlNonZero         LogCode = "lan_lldp.discover.lldpctl_nonzero"
	LogCodeLLDPSkipMalformedIface LogCode = "lan_lldp.discover.skip_malformed_interface"
)
