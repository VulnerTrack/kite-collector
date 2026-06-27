//go:build !linux && !darwin && !windows

package volumes

// newProbe is the no-op fallback for platforms (freebsd, openbsd) where
// we haven't wired an encryption detector yet. Mirrors the goreleaser
// release-matrix exclusion list.
func newProbe() EncryptionProbe { return noopProbe{} }
