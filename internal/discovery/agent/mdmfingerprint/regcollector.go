package mdmfingerprint

import (
	"context"
	"fmt"
)

// KeyProbe answers "does this HKLM subkey exist and does it contain at
// least one subkey?". The default implementation on Windows reads the
// live registry via golang.org/x/sys/windows/registry; on every other
// OS the default is a closed door. Tests inject their own probe so
// the table walk is exercisable on Linux CI.
type KeyProbe func(path string) (exists bool, hasSubkeys bool, err error)

// regCollector walks a slice of registrySignal entries through a
// KeyProbe and emits a Fingerprint for each hit. "Hit" requires both
// (exists==true) and either hasSubkeys==true (for collection roots
// like Enrollments\, OMADM\Accounts\, which only matter when populated)
// or the signal being a leaf key (we treat any signal where the parent
// path itself is the target as a leaf — see below).
type regCollector struct {
	name    string
	signals []registrySignal
	probe   KeyProbe
}

// NewRegistryCollector returns a Collector that probes the supplied
// registry signal table. Pass DefaultKeyProbe on Windows; tests pass
// a stub. Source on the returned State is fixed to SourceWindowsRegistry.
func NewRegistryCollector(signals []registrySignal, probe KeyProbe) Collector {
	if probe == nil {
		probe = func(string) (bool, bool, error) { return false, false, nil }
	}
	return &regCollector{
		name:    "mdm-fingerprint-winreg",
		signals: signals,
		probe:   probe,
	}
}

func (c *regCollector) Name() string { return c.name }

func (c *regCollector) Collect(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{Source: SourceWindowsRegistry}, fmt.Errorf("context cancelled: %w", err)
	}
	state := State{Source: SourceWindowsRegistry}
	for _, sig := range c.signals {
		if err := ctx.Err(); err != nil {
			return state, fmt.Errorf("context cancelled mid-scan: %w", err)
		}
		exists, hasSubkeys, err := c.probe(sig.Path)
		if err != nil {
			// Probe errors are non-fatal — surface as "not present"
			// so an ACL'd subtree cannot blow up a whole scan.
			continue
		}
		if !exists {
			continue
		}
		// For enrollment-record signals we require at least one
		// subkey: an empty HKLM\...\Enrollments\ root is a leftover
		// from a previous unenrollment and must not flag as managed.
		if sig.Kind == SignalEnrollmentRecord && !hasSubkeys {
			continue
		}
		state.Fingerprints = append(state.Fingerprints, Fingerprint{
			Vendor:     sig.Vendor,
			Product:    sig.Product,
			Kind:       sig.Kind,
			Evidence:   sig.Path,
			Confidence: sig.Confidence,
			Enrollment: sig.Enrollment,
		})
	}
	SortFingerprints(state.Fingerprints)
	Annotate(&state)
	return state, nil
}

// MergeStates folds two State values into one — used by the Windows
// collector to combine the filesystem and registry walks into a
// single result. The output Source is set to the first non-empty
// Source of the two inputs.
func MergeStates(a, b State) State {
	out := State{Source: a.Source}
	if out.Source == "" {
		out.Source = b.Source
	}
	out.Fingerprints = append(out.Fingerprints, a.Fingerprints...)
	out.Fingerprints = append(out.Fingerprints, b.Fingerprints...)
	SortFingerprints(out.Fingerprints)
	Annotate(&out)
	return out
}
