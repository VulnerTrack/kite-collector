package wsdiscovery

// LogCode — typed identifier for every structured log entry the
// wsdiscovery package emits. Convention: `lan_wsdiscovery.<surface>.<event>`.
type LogCode string

const (
	// discover surface — WS-Discovery multicast Probe lifecycle
	LogCodeWSDNoInterfaces   LogCode = "lan_wsdiscovery.discover.no_interfaces"
	LogCodeWSDIPv4ListenFail LogCode = "lan_wsdiscovery.discover.ipv4_listen_failed"
	LogCodeWSDIPv6ListenFail LogCode = "lan_wsdiscovery.discover.ipv6_listen_failed"
	LogCodeWSDOpenSenderFail LogCode = "lan_wsdiscovery.discover.open_sender_failed"
	LogCodeWSDSendFail       LogCode = "lan_wsdiscovery.discover.send_failed"
)
