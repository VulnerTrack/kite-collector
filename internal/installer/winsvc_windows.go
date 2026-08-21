//go:build windows

package installer

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// SetMachineEnv writes a machine-wide environment variable and broadcasts the
// change so already-running processes observe it without a reboot (R6).
//
// The broadcast is the half that is easy to forget and expensive to omit: the
// value lands in the registry immediately, but every process that started
// before the write keeps its inherited copy of the environment block until
// something sends WM_SETTINGCHANGE. Without it a freshly-installed collector
// service would not see KITE_OSQUERY_SOCKET until the host rebooted, and the
// osquery discovery source would sit inert with a WARN per scan.
//
// The broadcast fires even when the value was already correct: a value written
// by a previous install (or by the MSI) can still predate the environment block
// of a process running right now.
func SetMachineEnv(name, value string) error {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		machineEnvRegPath,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("open machine environment key: %w", err)
	}
	defer func() { _ = k.Close() }()

	current, _, getErr := k.GetStringValue(name)
	if getErr != nil || current != value {
		if setErr := k.SetStringValue(name, value); setErr != nil {
			return fmt.Errorf("set machine environment %s: %w", name, setErr)
		}
	}
	notifyEnvironmentChange()
	return nil
}

// ConfigureServiceRecovery configures Windows SCM failure-recovery actions for
// an already-registered service (R5) — the Windows counterpart of the Linux
// unit's Restart=on-failure / RestartSec=5.
//
// kardianos/service's cross-platform abstraction has no notion of recovery
// actions (its "Restart"/"KeepAlive" options are launchd/systemd concepts that
// map to nothing on Windows), which is exactly why the MSI's <ServiceInstall>
// never configured them either and why a crashed kite-osqueryd has, until now,
// stayed dead until a manual restart or reboot. This is the one Windows-only
// call that closes that gap; it must run *after* svc.Install() because it opens
// the service by name.
//
// SetRecoveryActionsOnNonCrashFailures is the non-obvious second half: by
// default SCM only counts a *crash* (non-zero exit / unhandled exception) as a
// failure. A daemon that exits 0 because it could not open its RocksDB
// database would otherwise never trip the recovery policy at all.
func ConfigureServiceRecovery(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer func() { _ = s.Close() }()

	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: OsqueryRestartDelay},
		{Type: mgr.ServiceRestart, Delay: OsqueryRestartDelay},
		{Type: mgr.ServiceRestart, Delay: OsqueryRestartDelayLater},
	}
	if setErr := s.SetRecoveryActions(actions, OsqueryRecoveryResetSeconds); setErr != nil {
		return fmt.Errorf("set recovery actions for %s: %w", serviceName, setErr)
	}
	if flagErr := s.SetRecoveryActionsOnNonCrashFailures(true); flagErr != nil {
		return fmt.Errorf("enable non-crash recovery for %s: %w", serviceName, flagErr)
	}
	return nil
}

// RecordInstallMarker records where this installer put things, so a later run
// can detect a prior self-contained install and upgrade it in place instead of
// laying down a second tree (R7).
//
// It writes into the same HKLM\SOFTWARE\VulnerTrack\KiteCollector key the MSI
// already uses, but only under value names the MSI does not own. Windows
// Installer removes exactly the values it created on uninstall, so the two
// writers share the key without either clobbering the other.
func RecordInstallMarker(opts Options, variant, version, osqueryVersion string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, vendorRegPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create vendor registry key: %w", err)
	}
	defer func() { _ = k.Close() }()

	values := []struct{ name, value string }{
		{vendorRegInstallLocation, opts.BinaryDir},
		{vendorRegVariant, variant},
		{vendorRegVersion, version},
		{vendorRegOsqueryVersion, osqueryVersion},
	}
	for _, v := range values {
		if v.value == "" {
			continue
		}
		if setErr := k.SetStringValue(v.name, v.value); setErr != nil {
			return fmt.Errorf("set marker value %s: %w", v.name, setErr)
		}
	}
	return nil
}

// installLogSDDL grants full control to BUILTIN\Administrators (BA) and
// NT AUTHORITY\SYSTEM (SY), and to nobody else. The leading "D:P" marks the
// DACL protected, which is the load-bearing part: without it %ProgramData%'s
// inheritable "Users: Read & Execute" ACE flows down and every interactive user
// on the box can read the install log (RFC-0156 Section 6.1, Information
// Disclosure).
const installLogSDDL = "D:P(A;;FA;;;BA)(A;;FA;;;SY)"

// HardenFileACL replaces a file's inherited ACL with the Administrators+SYSTEM
// DACL above.
func HardenFileACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(installLogSDDL)
	if err != nil {
		return fmt.Errorf("parse install-log SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read install-log DACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("apply install-log DACL to %s: %w", path, err)
	}
	return nil
}
