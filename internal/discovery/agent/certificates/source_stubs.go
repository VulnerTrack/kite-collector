package certificates

import "context"

// Stubs for sources not yet wired. Same pattern as other CDMS packages:
// return empty so the chain runs unconditionally.

// NewMacOSKeychainCollector returns a stub macOS Keychain collector.
//
// TODO(cdms-iter): shell-out to:
//
//	security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain
//
// for system roots, and:
//
//	security find-certificate -a -p ~/Library/Keychains/login.keychain-db
//
// for user store. Output is concatenated PEM — feed straight into
// ParsePEMBundle and stamp Store accordingly.
func NewMacOSKeychainCollector() Collector {
	return sourceStub{name: "macos-keychain-stub"}
}

// NewWindowsCertStoreCollector returns a stub Windows certstore collector.
//
// TODO(cdms-iter): wire CertEnumCertificatesInStore via crypt32.dll,
// or shell out to PowerShell:
//
//	Get-ChildItem Cert:\LocalMachine\Root | ConvertTo-Json -Depth 6
//
// then translate each row into a Certificate (use the same FromX509
// helper by re-parsing the raw bytes).
func NewWindowsCertStoreCollector() Collector {
	return sourceStub{name: "windows-certstore-stub"}
}

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Certificate, error) {
	return []Certificate{}, nil
}
