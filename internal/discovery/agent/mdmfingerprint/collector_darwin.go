//go:build darwin

package mdmfingerprint

// NewCollector returns the default Darwin filesystem collector rooted
// at "/". Tests construct an fsCollector directly via NewFSCollector
// with a t.TempDir() root.
func NewCollector() Collector {
	return NewFSCollector("mdm-fingerprint-darwin", SourceDarwinFS, macosSignals(), "")
}
