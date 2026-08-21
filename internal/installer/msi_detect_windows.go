//go:build windows

package installer

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// msiDisplayNamePrefix matches both products wix.wxs compiles: "Kite Collector"
// and "Kite Collector + osquery".
const msiDisplayNamePrefix = "Kite Collector"

const msiPublisher = "VulnerTrack"

// Registry locations consulted by the pre-flight check and by the marker the
// self-contained installer leaves behind.
const (
	uninstallRegPath    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	upgradeCodesRegPath = `SOFTWARE\Classes\Installer\UpgradeCodes`

	// machineEnvRegPath is where a machine-wide environment variable lives.
	// wixl (msitools) does not implement WiX's <Environment> element, so the
	// MSI writes KITE_OSQUERY_SOCKET here as a plain RegistryValue; this
	// installer writes the identical value to the identical place, which is
	// what keeps the two channels' env contract byte-identical (R6).
	machineEnvRegPath = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

	// vendorRegPath is created by the MSI (CertsDir, OsqueryDataDir,
	// OsqueryLogDir) and *extended* — never overwritten — by this installer
	// with its own marker values. Windows Installer only removes the values it
	// created, so the two writers coexist.
	vendorRegPath = `SOFTWARE\VulnerTrack\KiteCollector`

	vendorRegInstallLocation = "InstallLocation"
	vendorRegVariant         = "InstallerVariant"
	vendorRegVersion         = "InstallerVersion"
	vendorRegOsqueryVersion  = "BundledOsqueryVersion"
)

// DetectPriorInstall implements the R7 pre-flight check: find an installation
// this artifact should upgrade in place rather than side-install next to.
//
// Three lookups, most authoritative first:
//
//  1. The shared UpgradeCode. Windows Installer indexes every installed product
//     under HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\<packed upgrade code>,
//     whose value *names* are packed ProductCodes. This is the same identity
//     MajorUpgrade uses, so it finds exactly what a new MSI would replace.
//  2. A DisplayName/Publisher scan of the Uninstall key. Catches an install
//     whose UpgradeCodes entry was damaged — a repaired-registry or
//     manually-cleaned host — which would otherwise read as "fresh" and produce
//     the duplicate tree R7 exists to prevent.
//  3. This installer's own marker key, for a self-contained -> self-contained
//     upgrade (no MSI has ever touched the host).
//
// Every failure path degrades to "not found" rather than an error: a
// pre-flight check that cannot read the registry must not block an install that
// would otherwise succeed. The cost of a false negative is the duplicate-tree
// case RFC-0156 Section 8.1 already lists as a known, manually-recoverable
// failure mode; the cost of a false abort is an installer that refuses to run.
func DetectPriorInstall() PriorInstall {
	if p, ok := detectMSIByUpgradeCode(); ok {
		return p
	}
	if p, ok := detectMSIByUninstallScan(); ok {
		return p
	}
	if p, ok := detectSelfContainedInstall(); ok {
		return p
	}
	return PriorInstall{Kind: PriorInstallNone}
}

func detectMSIByUpgradeCode() (PriorInstall, bool) {
	packed, err := packMSIGUID(MSIUpgradeCode)
	if err != nil {
		return PriorInstall{}, false
	}
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		upgradeCodesRegPath+`\`+packed,
		registry.READ,
	)
	if err != nil {
		return PriorInstall{}, false
	}
	defer func() { _ = k.Close() }()

	packedProducts, err := k.ReadValueNames(0)
	if err != nil {
		return PriorInstall{}, false
	}
	for _, packedProduct := range packedProducts {
		productCode, unpackErr := unpackMSIGUID(packedProduct)
		if unpackErr != nil {
			continue
		}
		p, _, ok := readUninstallEntry(
			registry.LOCAL_MACHINE,
			uninstallRegPath+`\`+productCode,
		)
		if !ok {
			continue
		}
		p.Kind = PriorInstallMSI
		p.ProductCode = productCode
		return p, true
	}
	return PriorInstall{}, false
}

func detectMSIByUninstallScan() (PriorInstall, bool) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallRegPath, registry.READ)
	if err != nil {
		return PriorInstall{}, false
	}
	defer func() { _ = root.Close() }()

	subKeys, err := root.ReadSubKeyNames(0)
	if err != nil {
		return PriorInstall{}, false
	}
	for _, sub := range subKeys {
		p, publisher, ok := readUninstallEntry(root, sub)
		if !ok {
			continue
		}
		if !strings.HasPrefix(p.DisplayName, msiDisplayNamePrefix) {
			continue
		}
		// An empty Publisher is tolerated because this branch only runs when
		// the authoritative UpgradeCode lookup already failed, i.e. on a host
		// whose installer registry is known to be damaged. A wrong, non-empty
		// publisher is not tolerated: that would be some other vendor's
		// product that happens to share our display name.
		if publisher != "" && publisher != msiPublisher {
			continue
		}
		p.Kind = PriorInstallMSI
		p.ProductCode = sub
		return p, true
	}
	return PriorInstall{}, false
}

func detectSelfContainedInstall() (PriorInstall, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, vendorRegPath, registry.QUERY_VALUE)
	if err != nil {
		return PriorInstall{}, false
	}
	defer func() { _ = k.Close() }()

	location, _, err := k.GetStringValue(vendorRegInstallLocation)
	if err != nil || location == "" {
		return PriorInstall{}, false
	}
	version, _, _ := k.GetStringValue(vendorRegVersion)
	variant, _, _ := k.GetStringValue(vendorRegVariant)
	name := "Kite Collector"
	if variant != "" {
		name += " (" + variant + ")"
	}
	return PriorInstall{
		Kind:            PriorInstallSelfContained,
		DisplayName:     name,
		DisplayVersion:  version,
		InstallLocation: location,
	}, true
}

// readUninstallEntry reads one Add/Remove Programs entry, returning the entry
// and its Publisher separately (Publisher is a filter input for the fallback
// scan, not part of the install identity this package carries around).
// DisplayName is the only required value — an entry without one is a fragment
// Windows itself hides, not an installed product.
func readUninstallEntry(parent registry.Key, path string) (PriorInstall, string, bool) {
	k, err := registry.OpenKey(parent, path, registry.QUERY_VALUE)
	if err != nil {
		return PriorInstall{}, "", false
	}
	defer func() { _ = k.Close() }()

	name, _, err := k.GetStringValue("DisplayName")
	if err != nil || name == "" {
		return PriorInstall{}, "", false
	}
	p := PriorInstall{DisplayName: name}
	p.DisplayVersion, _, _ = k.GetStringValue("DisplayVersion")
	p.InstallLocation, _, _ = k.GetStringValue("InstallLocation")
	p.UninstallString, _, _ = k.GetStringValue("UninstallString")
	publisher, _, _ := k.GetStringValue("Publisher")
	return p, publisher, true
}
