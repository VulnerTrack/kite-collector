package mdns

// LogCode — typed identifier for every structured log entry the
// mdns package emits. Convention: `lan_mdns.<surface>.<event>`.
type LogCode string

const (
	// discover surface — multicast query/listen lifecycle
	LogCodeMDNSNoInterfaces   LogCode = "lan_mdns.discover.no_interfaces"
	LogCodeMDNSIPv4ListenFail LogCode = "lan_mdns.discover.ipv4_listen_failed"
	LogCodeMDNSIPv6ListenFail LogCode = "lan_mdns.discover.ipv6_listen_failed"
	LogCodeMDNSOpenSenderFail LogCode = "lan_mdns.discover.open_sender_failed"
	LogCodeMDNSBuildQueryFail LogCode = "lan_mdns.discover.build_query_failed"
	LogCodeMDNSSendFail       LogCode = "lan_mdns.discover.send_failed"
)
