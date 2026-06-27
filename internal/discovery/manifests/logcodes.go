package manifests

// LogCode is the typed identifier attached to every structured log
// entry the manifests discovery package emits. Convention:
// `manifests.<surface>.<event>` so downstream tooling can pivot on a
// stable identifier without parsing freeform message text.
//
// Two surfaces are exposed:
//   - `scanner`: the manifest scanner (source.go) — orchestrates the
//     walk, parses dependency manifests, and produces assets/findings.
//   - `walker`:  the filesystem walker (walker.go) — traverses scan
//     roots and emits matches.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- scanner (source.go) -----------------------------------------
	LogCodeScannerWalkComplete       LogCode = "manifests.scanner.walk_complete"
	LogCodeScannerDiscoveryComplete  LogCode = "manifests.scanner.discovery_complete"
	LogCodeScannerPathOutsideRoots   LogCode = "manifests.scanner.path_outside_scan_roots"
	LogCodeScannerReadError          LogCode = "manifests.scanner.read_error"
	LogCodeScannerParseError         LogCode = "manifests.scanner.parse_error"
	LogCodeScannerParseWarning       LogCode = "manifests.scanner.parse_warning"
	LogCodeScannerGitDetectionError  LogCode = "manifests.scanner.git_detection_error"
	LogCodeScannerLockfilePreference LogCode = "manifests.scanner.skip_manifest_for_lockfile"

	// --- walker (walker.go) ------------------------------------------
	LogCodeWalkerRootInaccessible LogCode = "manifests.walker.root_inaccessible"
	LogCodeWalkerRootNotDirectory LogCode = "manifests.walker.root_not_directory"
	LogCodeWalkerWalkError        LogCode = "manifests.walker.walk_error"
	LogCodeWalkerEntryError       LogCode = "manifests.walker.entry_error"
	LogCodeWalkerOversizedFile    LogCode = "manifests.walker.skipping_oversized_file"
)
