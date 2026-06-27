//go:build linux

package mdmfingerprint

// NewCollector returns the default Linux filesystem collector rooted
// at "/". Linux has no formal MDM protocol — what we detect here are
// the endpoint-management agents (JumpCloud, Tanium, Wazuh, Fleet,
// osquery) that play the same role for fleet operators.
func NewCollector() Collector {
	return NewFSCollector("mdm-fingerprint-linux", SourceLinuxFS, linuxSignals(), "")
}
