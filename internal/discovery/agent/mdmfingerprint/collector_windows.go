//go:build windows

package mdmfingerprint

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

// NewCollector returns the default Windows collector — a fan-out
// across (a) the filesystem fingerprint table and (b) the registry
// fingerprint table. Both feed into a single merged State so callers
// see one consistent view.
func NewCollector() Collector {
	fs := NewFSCollector("mdm-fingerprint-windows-fs", SourceWindowsFS, windowsFSSignals(), "")
	reg := NewRegistryCollector(windowsRegistrySignals(), DefaultKeyProbe)
	return &windowsComposite{fs: fs, reg: reg}
}

// DefaultKeyProbe queries HKEY_LOCAL_MACHINE for the supplied subkey
// path and reports whether it exists and whether it has any subkeys
// of its own. ACL-denied opens are folded into (false, false, err).
func DefaultKeyProbe(path string) (bool, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		// ErrNotExist is the common case and not a real error.
		return false, false, nil //nolint:nilerr // intentional
	}
	defer func() { _ = k.Close() }()
	subs, err := k.ReadSubKeyNames(1)
	if err != nil {
		// Key opened but enumeration failed (e.g. partial ACL) —
		// treat as "exists but empty" rather than dropping the hit.
		return true, false, nil //nolint:nilerr // intentional
	}
	return true, len(subs) > 0, nil
}

type windowsComposite struct {
	fs  Collector
	reg Collector
}

func (w *windowsComposite) Name() string { return "mdm-fingerprint-windows" }

func (w *windowsComposite) Collect(ctx context.Context) (State, error) {
	fsState, fsErr := w.fs.Collect(ctx)
	regState, regErr := w.reg.Collect(ctx)
	merged := MergeStates(fsState, regState)
	// Surface the first error encountered — but only after Merging,
	// so partial results still land.
	if fsErr != nil {
		return merged, fsErr
	}
	return merged, regErr
}
