package ssdp

// LogCode — typed identifier for every structured log entry the
// ssdp package emits. Convention: `lan_ssdp.<surface>.<event>`.
type LogCode string

const (
	// discover surface — SSDP multicast M-SEARCH lifecycle
	LogCodeSSDPNoInterfaces   LogCode = "lan_ssdp.discover.no_interfaces"
	LogCodeSSDPIPv4ListenFail LogCode = "lan_ssdp.discover.ipv4_listen_failed"
	LogCodeSSDPIPv6ListenFail LogCode = "lan_ssdp.discover.ipv6_listen_failed"
	LogCodeSSDPOpenSenderFail LogCode = "lan_ssdp.discover.open_sender_failed"
	LogCodeSSDPSendFail       LogCode = "lan_ssdp.discover.send_failed"
)
