package installer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MSIUpgradeCode is the UpgradeCode both kite-collector MSI products share
// (cmd/kite-collector/wix.wxs). It is fixed for the life of the product — the
// plain and the +osquery MSI declare the same value precisely so installing
// either replaces the other instead of side-installing.
//
// The self-contained .exe is not an MSI and therefore has no UpgradeCode of its
// own. RFC-0156 Section 4.2 is explicit that this makes R7 a *behavioral*
// substitute for the shared-upgrade-identity axiom rather than a
// database-level one: the installer reads this code out of the registry to
// discover a prior MSI install and upgrades that tree in place.
const MSIUpgradeCode = "19b944d3-493b-4a20-952d-df1c6b0e2fe3"

// Prior-install kinds. Empty means nothing was found.
const (
	PriorInstallNone          = ""
	PriorInstallMSI           = "msi"
	PriorInstallSelfContained = "self_contained"
)

// preflight_result tokens, matching InstallationRun in RFC-0156 Section 4.1.
const (
	PreflightFreshInstall             = "fresh_install"
	PreflightUpgradeFromMSI           = "upgrade_from_msi"
	PreflightUpgradeFromSelfContained = "upgrade_from_self_contained"
)

// PriorInstall is what the pre-flight check found on the host. A zero value
// means a fresh install.
//
// InstallLocation is the field R7 actually turns on: when a prior install
// names a directory, the new payload is written *there* rather than into this
// binary's own smart default. Two Program Files trees both claiming the
// "kite-collector" service name is the duplicate-install failure this avoids —
// SCM can only hold one registration, so the loser becomes orphaned files plus
// a stale Add/Remove Programs entry whose uninstall would rip out the winner's
// service.
type PriorInstall struct {
	Kind            string `json:"kind"`
	DisplayName     string `json:"display_name,omitempty"`
	DisplayVersion  string `json:"display_version,omitempty"`
	ProductCode     string `json:"product_code,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	UninstallString string `json:"uninstall_string,omitempty"`
}

// Found reports whether anything was detected.
func (p PriorInstall) Found() bool { return p.Kind != PriorInstallNone }

// PreflightResult maps the detection onto the InstallationRun vocabulary.
func (p PriorInstall) PreflightResult() string {
	switch p.Kind {
	case PriorInstallMSI:
		return PreflightUpgradeFromMSI
	case PriorInstallSelfContained:
		return PreflightUpgradeFromSelfContained
	default:
		return PreflightFreshInstall
	}
}

// packMSIGUID converts a canonical GUID to the "compressed" form Windows
// Installer uses as a registry key name under Installer\UpgradeCodes and
// Installer\Products.
//
// The transform is: reverse the first 8 hex digits, reverse the next 4, reverse
// the next 4, then byte-swap each of the remaining 8 pairs. It is its own
// inverse, which is what unpackMSIGUID relies on.
//
// Kept here rather than in the Windows-only file because it is pure string
// arithmetic with an exactly-known answer — the one part of the pre-flight
// check that can be unit-tested on the Linux CI that actually runs the tests.
func packMSIGUID(guid string) (string, error) {
	h, err := normalizeGUIDHex(guid)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(32)
	b.WriteString(reverseASCII(h[0:8]))
	b.WriteString(reverseASCII(h[8:12]))
	b.WriteString(reverseASCII(h[12:16]))
	for i := 16; i < 32; i += 2 {
		b.WriteByte(h[i+1])
		b.WriteByte(h[i])
	}
	return b.String(), nil
}

// unpackMSIGUID converts a compressed registry GUID back to the braced
// canonical form the Uninstall key is named with.
func unpackMSIGUID(packed string) (string, error) {
	h, err := normalizeGUIDHex(packed)
	if err != nil {
		return "", err
	}
	var tail strings.Builder
	tail.Grow(16)
	for i := 16; i < 32; i += 2 {
		tail.WriteByte(h[i+1])
		tail.WriteByte(h[i])
	}
	t := tail.String()
	return "{" + strings.Join([]string{
		reverseASCII(h[0:8]),
		reverseASCII(h[8:12]),
		reverseASCII(h[12:16]),
		t[0:4],
		t[4:16],
	}, "-") + "}", nil
}

// normalizeGUIDHex strips braces/dashes/whitespace and validates that exactly
// 32 uppercase hex digits remain.
func normalizeGUIDHex(guid string) (string, error) {
	h := strings.ToUpper(strings.NewReplacer(
		"{", "", "}", "", "-", "", " ", "", "\t", "",
	).Replace(strings.TrimSpace(guid)))
	if len(h) != 32 {
		return "", fmt.Errorf("guid %q: want 32 hex digits, got %d", guid, len(h))
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		isDigit := c >= '0' && c <= '9'
		isHexUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isHexUpper {
			return "", fmt.Errorf("guid %q: non-hex character %q", guid, string(c))
		}
	}
	return h, nil
}

// reverseASCII reverses a string of ASCII bytes. Safe here because the input is
// always validated hex.
func reverseASCII(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// MSIProductDirName is the INSTALLFOLDER name in cmd/kite-collector/wix.wxs.
// Note the space: the MSI installs to "%ProgramFiles%\Kite Collector" while
// DefaultBinaryDir resolves to "%ProgramFiles%\kite-collector". That
// divergence is the path-naming drift RFC-0156 Section 2.1 documents and R7
// bridges — the two channels can each keep their own convention as long as the
// installer notices the other one and does not lay down a second tree.
const MSIProductDirName = "Kite Collector"

// MSIDefaultInstallDir is where the MSI puts things when nothing overrode it.
//
// It is a *fallback* for R7, not the primary signal: wix.wxs does not set
// ARPINSTALLLOCATION, so the Uninstall key's InstallLocation value is usually
// empty for our own MSIs. Without this fallback the pre-flight check would
// detect the prior install correctly and then still write the new payload into
// the wizard's own directory — a duplicate tree, which is exactly the outcome
// R7 exists to prevent.
func MSIDefaultInstallDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, MSIProductDirName)
}

// ResolveInstallDir applies the R7 pre-flight decision to the smart defaults:
// when a prior installation exists, its directory wins, so the new payload
// upgrades that tree in place instead of side-installing next to it.
//
// A per-user install never adopts a machine-wide MSI tree — it has no
// privileges to write there, and inheriting the path would turn a working
// unprivileged install into a permission-denied abort.
func ResolveInstallDir(opts Options, prior PriorInstall) string {
	if opts.UserMode || !prior.Found() {
		return opts.BinaryDir
	}
	if dir := strings.TrimSpace(prior.InstallLocation); dir != "" && isExistingDir(dir) {
		return filepath.Clean(dir)
	}
	if prior.Kind == PriorInstallMSI {
		if dir := MSIDefaultInstallDir(); dir != "" && isExistingDir(dir) {
			return dir
		}
	}
	return opts.BinaryDir
}

func isExistingDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// installDirAllowRootVars are the environment variables whose values bound
// where an operator-supplied /DIR= may point.
var installDirAllowRootVars = []string{
	"ProgramFiles",
	"ProgramW6432",
	"ProgramFiles(x86)",
	"LOCALAPPDATA",
}

// ValidateInstallDir bounds the unattended installer's /DIR= override
// (RFC-0156 Section 5.4).
//
// The override reaches an elevated process that then writes an executable and
// points a LocalSystem service at it, so an unvalidated path is a
// privilege-escalation primitive, not a UX detail: "/DIR=C:\Users\bob\AppData"
// would have SCM launch a binary any unprivileged user can replace. Mirrors
// RFC-0057's path-injection hardening precedent — resolve first, then require
// the result to sit strictly *under* an allow-listed root, so `..` traversal is
// eliminated by construction rather than pattern-matched away.
func ValidateInstallDir(dir string) error {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return errors.New("install directory is empty")
	}
	cleaned := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("install directory %q must be an absolute path", dir)
	}
	roots := make([]string, 0, len(installDirAllowRootVars))
	for _, name := range installDirAllowRootVars {
		if p := os.Getenv(name); p != "" {
			roots = append(roots, filepath.Clean(p))
		}
	}
	if len(roots) == 0 {
		return errors.New("no allow-listed install root is present in the environment")
	}
	for _, root := range roots {
		if pathStrictlyWithin(root, cleaned) {
			return nil
		}
	}
	return fmt.Errorf(
		"install directory %q is outside the allowed roots %s",
		dir, strings.Join(roots, ", "))
}

// pathStrictlyWithin reports whether candidate is a proper descendant of root.
// Equality is rejected on purpose: installing directly into %ProgramFiles% is
// never what an operator meant.
func pathStrictlyWithin(root, candidate string) bool {
	if within(root, candidate) {
		return true
	}
	if runtime.GOOS != "windows" {
		return false
	}
	// Windows paths are case-insensitive; retry folded so
	// "c:\program files\..." matches a "C:\Program Files" root.
	return within(strings.ToLower(root), strings.ToLower(candidate))
}

func within(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}
