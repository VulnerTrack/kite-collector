package mdmfingerprint

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// fsCollector walks a fingerprint table and reports a Fingerprint for
// every path that exists under Root. Root defaults to "/" but tests
// inject a t.TempDir() so a fixture filesystem stands in for the real
// host. The same struct serves the macOS and Linux collectors; the
// only per-OS bit is which table they pass in.
type fsCollector struct {
	name    string
	source  Source
	signals map[string]signalSpec
	root    string
}

// NewFSCollector returns a Collector that probes the local filesystem
// against the supplied signal table. Callers pass an empty root to
// scan the real host, or a directory prefix to scan a fixture tree.
//
// The collector is read-only: it never opens files, never lists
// directory contents, and never follows symlinks beyond the one
// os.Lstat call needed to decide existence. Permission-denied errors
// are folded silently — the audit pipeline can re-run as root if it
// needs richer coverage.
func NewFSCollector(name string, source Source, signals map[string]signalSpec, root string) Collector {
	return &fsCollector{
		name:    name,
		source:  source,
		signals: signals,
		root:    root,
	}
}

func (c *fsCollector) Name() string { return c.name }

func (c *fsCollector) Collect(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{Source: c.source}, fmt.Errorf("context cancelled: %w", err)
	}
	state := State{Source: c.source}
	for path, spec := range c.signals {
		if err := ctx.Err(); err != nil {
			return state, fmt.Errorf("context cancelled mid-scan: %w", err)
		}
		full := joinUnder(c.root, path)
		if !pathExists(full) {
			continue
		}
		state.Fingerprints = append(state.Fingerprints, Fingerprint{
			Vendor:     spec.Vendor,
			Product:    spec.Product,
			Kind:       spec.Kind,
			Evidence:   path,
			Confidence: spec.Confidence,
			Enrollment: spec.Enrollment,
		})
	}
	SortFingerprints(state.Fingerprints)
	Annotate(&state)
	return state, nil
}

// joinUnder grafts an absolute fingerprint path onto a root prefix.
// On Windows the table uses forward slashes and a "C:" drive letter;
// when root is non-empty (test fixture mode) we strip the drive so
// the join lands inside the fixture tree regardless of host OS.
func joinUnder(root, abs string) string {
	if root == "" || root == "/" {
		return abs
	}
	clean := abs
	if len(clean) >= 2 && clean[1] == ':' {
		// Strip a drive letter (e.g. "C:") so the join works on
		// non-Windows test runners.
		clean = clean[2:]
	}
	clean = strings.TrimPrefix(clean, "/")
	clean = strings.TrimPrefix(clean, `\`)
	clean = filepath.FromSlash(clean)
	return filepath.Join(root, clean)
}

// pathExists reports whether path resolves to anything — file,
// directory, or symlink. Permission-denied and not-exist both
// return false; any other error is treated as "not present" so a
// flaky filesystem cannot crash a scan.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return false
}
