// Package mdmfingerprint detects which MDM / UEM / endpoint-management
// agents are installed on the local host and whether the host is actively
// enrolled. It is the cross-platform complement to macosmobileconfig
// (which parses .mobileconfig payload contents on macOS).
//
// Each per-OS Collector walks a curated table of fingerprints
// (filesystem paths plus, on Windows, registry keys) and reports a
// Fingerprint per vendor signal it finds. A signal can be:
//
//   - an installed agent binary or daemon plist / systemd unit
//     (Confidence=medium, Enrollment=false), or
//   - an active enrollment marker such as an Apple cloud-config
//     activation record or a Windows OMADM account
//     (Confidence=high, Enrollment=true).
//
// Read-only by intent: collectors never write, never network, never
// shell out beyond the platform-stable APIs already used elsewhere in
// the agent. (Matches the rest of internal/discovery/agent/* and the
// kite-collector security posture.)
package mdmfingerprint

import (
	"context"
	"sort"
	"strings"
)

// Vendor identifies a known MDM, UEM, or endpoint-management vendor.
type Vendor string

const (
	VendorJamf         Vendor = "jamf"
	VendorKandji       Vendor = "kandji"
	VendorMosyle       Vendor = "mosyle"
	VendorAddigy       Vendor = "addigy"
	VendorIntune       Vendor = "intune"
	VendorWorkspaceOne Vendor = "workspace-one"
	VendorFleetDM      Vendor = "fleetdm"
	VendorMunki        Vendor = "munki"
	VendorJumpCloud    Vendor = "jumpcloud"
	VendorTanium       Vendor = "tanium"
	VendorWazuh        Vendor = "wazuh"
	VendorOsquery      Vendor = "osquery"
	// VendorAppleMDM is the generic Apple MDM enrollment signal — set
	// when /var/db/ConfigurationProfiles shows an active activation
	// record but no vendor-specific agent was identified alongside it.
	VendorAppleMDM Vendor = "apple-mdm"
	// VendorWindowsMDM is the generic Windows MDM (OMADM) enrollment
	// signal, set when an HKLM\...\Enrollments\<guid> entry exists.
	VendorWindowsMDM Vendor = "windows-mdm"
)

// SignalKind classifies a single piece of evidence so the orchestrator
// can decide how to weight it.
type SignalKind string

const (
	// SignalAgentBinary is an installed management-agent executable.
	SignalAgentBinary SignalKind = "agent-binary"
	// SignalDaemonUnit is a system service (launchd plist, systemd
	// unit, Windows service registration) that runs the agent.
	SignalDaemonUnit SignalKind = "daemon-unit"
	// SignalConfigDir is an installed config / data directory.
	SignalConfigDir SignalKind = "config-dir"
	// SignalEnrollmentRecord is a hard enrollment marker (Apple cloud
	// activation record, Windows OMADM account, MDM enrollment cert).
	SignalEnrollmentRecord SignalKind = "enrollment-record"
)

// Confidence ranks how certain a single signal is.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Source identifies which collector path produced a State.
type Source string

const (
	SourceDarwinFS  Source = "darwin-fs"
	SourceLinuxFS   Source = "linux-fs"
	SourceWindowsFS Source = "windows-fs"
	SourceWindowsRegistry Source = "windows-registry"
	SourceNoProbe   Source = "no-probe"
)

// Fingerprint is a single positive match against the vendor table.
type Fingerprint struct {
	Vendor     Vendor     `json:"vendor"`
	Product    string     `json:"product"`
	Kind       SignalKind `json:"kind"`
	Evidence   string     `json:"evidence"`
	Confidence Confidence `json:"confidence"`
	// Enrollment is true when the signal proves the host is currently
	// enrolled, not merely that an agent is installed.
	Enrollment bool `json:"enrollment"`
}

// State is the read-only outcome of a single Collect() call.
type State struct {
	Source       Source        `json:"source"`
	Fingerprints []Fingerprint `json:"fingerprints"`
	// IsMDMManaged rolls up the fingerprints into the single boolean
	// the asset pipeline cares about: any high-confidence enrollment
	// signal, or any medium-confidence signal at all.
	IsMDMManaged bool `json:"is_mdm_managed"`
	// Vendors is the de-duplicated, sorted list of vendors observed —
	// useful as an asset tag value without re-walking Fingerprints.
	Vendors []Vendor `json:"vendors"`
}

// Collector is the contract every per-OS implementation satisfies.
// Non-target OSes return State{Source: SourceNoProbe} so callers can
// distinguish "host isn't this OS" from "we forgot to wire the probe".
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// signalSpec is one row of the vendor table. The OS-specific collector
// supplies the evidence path; this package owns vendor metadata and
// the rule for how a hit upgrades into a Fingerprint.
type signalSpec struct {
	Vendor     Vendor
	Product    string
	Kind       SignalKind
	Confidence Confidence
	Enrollment bool
}

// macosSignals describes the Darwin fingerprint table. Paths are
// absolute on a real macOS host; collector_darwin.go can rewrite the
// root for tests via a chroot prefix.
//
//nolint:gocyclo // table-driven, just data.
func macosSignals() map[string]signalSpec {
	return map[string]signalSpec{
		// Generic Apple MDM enrollment markers — these prove the host
		// is actively under some MDM authority.
		"/var/db/ConfigurationProfiles/Settings/.cloudConfigHasActivationRecord": {
			Vendor:     VendorAppleMDM,
			Product:    "Apple MDM (cloud activation record)",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
		"/var/db/ConfigurationProfiles/Settings/.profilesAreInstalled": {
			Vendor:     VendorAppleMDM,
			Product:    "Apple MDM (installed profile marker)",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
		"/var/db/ConfigurationProfiles/Store/MDM.plist": {
			Vendor:     VendorAppleMDM,
			Product:    "Apple MDM (MDM payload store)",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
		// Jamf Pro.
		"/usr/local/jamf/bin/jamf": {
			Vendor:     VendorJamf,
			Product:    "Jamf Pro agent",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/Library/Application Support/JAMF": {
			Vendor:     VendorJamf,
			Product:    "Jamf Pro support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		"/Library/LaunchDaemons/com.jamfsoftware.task.1.plist": {
			Vendor:     VendorJamf,
			Product:    "Jamf Pro launchd task",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// Kandji.
		"/Library/Kandji/Kandji Agent.app": {
			Vendor:     VendorKandji,
			Product:    "Kandji agent",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/Library/LaunchDaemons/io.kandji.KandjiDaemon.plist": {
			Vendor:     VendorKandji,
			Product:    "Kandji daemon",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// Mosyle Business / Manager.
		"/Library/LaunchDaemons/com.mosyle.business.plist": {
			Vendor:     VendorMosyle,
			Product:    "Mosyle daemon",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		"/Library/Application Support/Mosyle": {
			Vendor:     VendorMosyle,
			Product:    "Mosyle support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		// Addigy.
		"/Library/Addigy": {
			Vendor:     VendorAddigy,
			Product:    "Addigy support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		"/Library/LaunchDaemons/com.addigy.go-agent.plist": {
			Vendor:     VendorAddigy,
			Product:    "Addigy go-agent",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// Microsoft Intune Company Portal.
		"/Library/Intune/Microsoft Intune Agent.app": {
			Vendor:     VendorIntune,
			Product:    "Microsoft Intune agent",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/Library/Application Support/Microsoft/Intune": {
			Vendor:     VendorIntune,
			Product:    "Microsoft Intune support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		// VMware Workspace ONE / AirWatch.
		"/Library/Application Support/AirWatch": {
			Vendor:     VendorWorkspaceOne,
			Product:    "Workspace ONE / AirWatch support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		"/Library/LaunchDaemons/com.air-watch.mac.agent.plist": {
			Vendor:     VendorWorkspaceOne,
			Product:    "Workspace ONE agent daemon",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// FleetDM Orbit (osquery management).
		"/Library/LaunchDaemons/com.fleetdm.orbit.plist": {
			Vendor:     VendorFleetDM,
			Product:    "FleetDM Orbit daemon",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		"/opt/orbit/bin/orbit": {
			Vendor:     VendorFleetDM,
			Product:    "FleetDM Orbit binary",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		// Munki.
		"/Library/Managed Installs": {
			Vendor:     VendorMunki,
			Product:    "Munki managed installs data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		"/usr/local/munki/managedsoftwareupdate": {
			Vendor:     VendorMunki,
			Product:    "Munki updater binary",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		// osquery (often paired with Fleet but also standalone).
		"/var/osquery/osquery.db": {
			Vendor:     VendorOsquery,
			Product:    "osquery state DB",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceLow,
		},
	}
}

// linuxSignals describes the Linux fingerprint table. Linux does not
// have a formal MDM protocol; what we detect here are endpoint-
// management agents that play the same role (push policy, inventory,
// remote command) for fleet operators.
func linuxSignals() map[string]signalSpec {
	return map[string]signalSpec{
		// JumpCloud.
		"/opt/jc/bin/jumpcloud-agent": {
			Vendor:     VendorJumpCloud,
			Product:    "JumpCloud agent",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/lib/systemd/system/jcagent.service": {
			Vendor:     VendorJumpCloud,
			Product:    "JumpCloud agent service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		"/etc/systemd/system/jcagent.service": {
			Vendor:     VendorJumpCloud,
			Product:    "JumpCloud agent service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// Tanium.
		"/opt/Tanium/TaniumClient/TaniumClient": {
			Vendor:     VendorTanium,
			Product:    "Tanium client binary",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/lib/systemd/system/taniumclient.service": {
			Vendor:     VendorTanium,
			Product:    "Tanium client service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// Wazuh.
		"/var/ossec/bin/wazuh-agentd": {
			Vendor:     VendorWazuh,
			Product:    "Wazuh agent daemon",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/lib/systemd/system/wazuh-agent.service": {
			Vendor:     VendorWazuh,
			Product:    "Wazuh agent service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// FleetDM Orbit on Linux.
		"/opt/orbit/bin/orbit": {
			Vendor:     VendorFleetDM,
			Product:    "FleetDM Orbit binary",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		"/lib/systemd/system/orbit.service": {
			Vendor:     VendorFleetDM,
			Product:    "FleetDM Orbit service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceMedium,
		},
		// osquery standalone.
		"/var/osquery/osquery.db": {
			Vendor:     VendorOsquery,
			Product:    "osquery state DB",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceLow,
		},
		"/lib/systemd/system/osqueryd.service": {
			Vendor:     VendorOsquery,
			Product:    "osqueryd service",
			Kind:       SignalDaemonUnit,
			Confidence: ConfidenceLow,
		},
	}
}

// windowsFSSignals describes the filesystem half of the Windows table.
// Paths use forward slashes and a "C:" prefix so the same table works
// in test fixtures rooted at any directory.
func windowsFSSignals() map[string]signalSpec {
	return map[string]signalSpec{
		// Microsoft Intune Management Extension.
		`C:/Program Files (x86)/Microsoft Intune Management Extension/Microsoft.Management.Services.IntuneWindowsAgent.exe`: {
			Vendor:     VendorIntune,
			Product:    "Intune Management Extension",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		`C:/Program Files (x86)/Microsoft Intune Management Extension`: {
			Vendor:     VendorIntune,
			Product:    "Intune Management Extension support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		// Workspace ONE / AirWatch.
		`C:/Program Files (x86)/Airwatch/AgentUI/AW.WinPC.AgentUI.exe`: {
			Vendor:     VendorWorkspaceOne,
			Product:    "Workspace ONE agent UI",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		`C:/Program Files (x86)/Airwatch`: {
			Vendor:     VendorWorkspaceOne,
			Product:    "Workspace ONE support data",
			Kind:       SignalConfigDir,
			Confidence: ConfidenceMedium,
		},
		// Jamf Pro for Windows (rare but exists).
		`C:/Program Files/Jamf/bin/jamf.exe`: {
			Vendor:     VendorJamf,
			Product:    "Jamf Pro for Windows",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
		// Tanium.
		`C:/Program Files (x86)/Tanium/Tanium Client/TaniumClient.exe`: {
			Vendor:     VendorTanium,
			Product:    "Tanium client",
			Kind:       SignalAgentBinary,
			Confidence: ConfidenceMedium,
		},
	}
}

// windowsRegistrySignals is the registry half. The collector evaluates
// the parent path's existence (any subkey present = match). Real
// enrollment GUIDs live under HKLM\SOFTWARE\Microsoft\Enrollments\
// and HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\.
func windowsRegistrySignals() []registrySignal {
	return []registrySignal{
		{
			Path:   `SOFTWARE\Microsoft\Enrollments`,
			Vendor: VendorWindowsMDM,
			Product: "Windows OMA-DM enrollment",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
		{
			Path:   `SOFTWARE\Microsoft\Provisioning\OMADM\Accounts`,
			Vendor: VendorWindowsMDM,
			Product: "Windows OMA-DM accounts",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
		// Intune leaves a dedicated PolicyManager hive when enrolled.
		{
			Path:   `SOFTWARE\Microsoft\PolicyManager\current\device`,
			Vendor: VendorIntune,
			Product: "Intune PolicyManager device policy",
			Kind:       SignalEnrollmentRecord,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		},
	}
}

// registrySignal is the Windows-registry analogue of signalSpec. The
// collector matches on subkey presence rather than file existence.
type registrySignal struct {
	Path       string
	Vendor     Vendor
	Product    string
	Kind       SignalKind
	Confidence Confidence
	Enrollment bool
}

// MacOSSignals exports the macOS table for tests outside this package.
func MacOSSignals() map[string]signalSpec { return macosSignals() }

// LinuxSignals exports the Linux table for tests outside this package.
func LinuxSignals() map[string]signalSpec { return linuxSignals() }

// WindowsFSSignals exports the Windows filesystem table for tests.
func WindowsFSSignals() map[string]signalSpec { return windowsFSSignals() }

// WindowsRegistrySignals exports the Windows registry table for tests.
func WindowsRegistrySignals() []registrySignal { return windowsRegistrySignals() }

// Annotate fills State.IsMDMManaged and State.Vendors from a populated
// Fingerprints slice. Collectors call this once after they finish
// scanning so the rollup logic lives in one place.
func Annotate(s *State) {
	seen := make(map[Vendor]struct{}, len(s.Fingerprints))
	managed := false
	for _, fp := range s.Fingerprints {
		seen[fp.Vendor] = struct{}{}
		if fp.Enrollment {
			managed = true
		}
		if fp.Confidence == ConfidenceHigh || fp.Confidence == ConfidenceMedium {
			managed = true
		}
	}
	s.IsMDMManaged = managed
	s.Vendors = s.Vendors[:0]
	for v := range seen {
		s.Vendors = append(s.Vendors, v)
	}
	sort.Slice(s.Vendors, func(i, j int) bool {
		return s.Vendors[i] < s.Vendors[j]
	})
}

// SortFingerprints orders Fingerprints deterministically — by vendor
// then evidence path — so downstream JSON / hash output is stable.
func SortFingerprints(fps []Fingerprint) {
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Vendor != fps[j].Vendor {
			return fps[i].Vendor < fps[j].Vendor
		}
		return fps[i].Evidence < fps[j].Evidence
	})
}

// TagsFromVendors returns asset-tag map entries representing the
// observed MDM vendors. The keys are pinned to "mdm" and "mdm.<vendor>"
// for one-shot lookups in downstream consumers.
func TagsFromVendors(vs []Vendor) map[string]string {
	if len(vs) == 0 {
		return nil
	}
	names := make([]string, 0, len(vs))
	for _, v := range vs {
		names = append(names, string(v))
	}
	sort.Strings(names)
	out := map[string]string{
		"mdm": strings.Join(names, ","),
	}
	for _, n := range names {
		out["mdm."+n] = "true"
	}
	return out
}
