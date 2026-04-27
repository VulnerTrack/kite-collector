package resource

import (
	"bufio"
	"os"
	"runtime"
)

// OSDetectPolicy is a single host-OS detection rule. Detect returns the
// resource attribute triple (osType, osName, osVersion) and ok=true when
// the policy can confidently identify the host; ok=false signals "not
// applicable, try the next policy". A Name is included so detection can
// be observed in logs and tests.
type OSDetectPolicy interface {
	Name() string
	Detect() (osType, osName, osVersion string, ok bool)
}

// OSDetector evaluates a sequence of policies in order and returns the
// first match. It mirrors the rule-engine idiom used by
// internal/policy/engine.go: data-driven, ordered, first-match-wins.
//
// The detector is safe for concurrent use; each policy is consulted at
// Detect-time so no shared mutable state lives on the detector.
type OSDetector struct {
	policies []OSDetectPolicy
}

// NewOSDetector returns a detector that evaluates the given policies in
// order. The last policy SHOULD be unconditional (RuntimeFallbackPolicy)
// so Detect always produces a triple.
func NewOSDetector(policies ...OSDetectPolicy) *OSDetector {
	return &OSDetector{policies: policies}
}

// Detect walks the policy list and returns the first match. When no policy
// claims the host, the detector returns (runtime.GOOS, runtime.GOOS,
// "unknown") so the contract's required keys are always populated.
func (d *OSDetector) Detect() (osType, osName, osVersion string) {
	for _, p := range d.policies {
		if t, n, v, ok := p.Detect(); ok {
			return t, n, v
		}
	}
	return runtime.GOOS, runtime.GOOS, "unknown"
}

// defaultOSDetector is the chain wired in by Build. Tests construct their
// own detector by passing fake policies to NewOSDetector.
func defaultOSDetector() *OSDetector {
	return NewOSDetector(
		NewLinuxOSReleasePolicy(),
		RuntimeFallbackPolicy{},
	)
}

// ---------------------------------------------------------------------------
// Concrete policies
// ---------------------------------------------------------------------------

// LinuxOSReleasePolicy parses /etc/os-release on Linux. The path is
// injectable to keep the policy testable on any host.
type LinuxOSReleasePolicy struct {
	path string
}

// NewLinuxOSReleasePolicy returns a policy that reads /etc/os-release.
func NewLinuxOSReleasePolicy() LinuxOSReleasePolicy {
	return LinuxOSReleasePolicy{path: "/etc/os-release"}
}

// Name implements OSDetectPolicy.
func (LinuxOSReleasePolicy) Name() string { return "linux:os-release" }

// Detect implements OSDetectPolicy.
func (p LinuxOSReleasePolicy) Detect() (string, string, string, bool) {
	if runtime.GOOS != "linux" {
		return "", "", "", false
	}
	id, version, ok := readOSRelease(p.path)
	if !ok {
		return "", "", "", false
	}
	return "linux", orDefault(id, "linux"), orDefault(version, "unknown"), true
}

// RuntimeFallbackPolicy is the unconditional last-resort policy. It always
// matches and reports runtime.GOOS for both type and name.
type RuntimeFallbackPolicy struct{}

// Name implements OSDetectPolicy.
func (RuntimeFallbackPolicy) Name() string { return "runtime:fallback" }

// Detect implements OSDetectPolicy.
func (RuntimeFallbackPolicy) Detect() (string, string, string, bool) {
	return runtime.GOOS, runtime.GOOS, "unknown", true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readOSRelease parses an os-release-formatted file and returns
// (ID, VERSION_ID, ok). ok is false when the file is unreadable.
func readOSRelease(path string) (id, versionID string, ok bool) {
	f, err := os.Open(path) //#nosec G304 -- path injected by trusted policy registration
	if err != nil {
		return "", "", false
	}
	defer func() { _ = f.Close() }()

	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v := splitOSReleaseLine(s.Text())
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		}
	}
	return id, versionID, true
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
