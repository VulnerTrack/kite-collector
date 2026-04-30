package driver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// ProcModules collects loaded Linux kernel modules from /proc/modules and
// enriches them with .modinfo metadata, on-disk SHA-256, and the kernel
// taint flags. Read-only on every codepath.
type ProcModules struct {
	now        func() time.Time
	procPath   string // /proc/modules — overridable for tests
	taintPath  string // /proc/sys/kernel/tainted — overridable for tests
	modulesDir string // /lib/modules/<uname -r> — overridable for tests
}

// NewProcModules constructs a ProcModules with the kernel-default paths.
func NewProcModules() *ProcModules {
	return &ProcModules{
		procPath:   "/proc/modules",
		taintPath:  "/proc/sys/kernel/tainted",
		modulesDir: "",
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for the registry.
func (p *ProcModules) Name() string { return "linux-procmodules" }

// Available returns true on Linux when /proc/modules is readable.
func (p *ProcModules) Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat(p.procPath); err != nil {
		return false
	}
	return true
}

// Collect parses /proc/modules and decorates each entry. The kernel taint
// is global (not per-module) but is attached to every row to expose
// "any unsigned module loaded" as a per-record signal.
func (p *ProcModules) Collect(ctx context.Context) (*Result, error) {
	_ = ctx // current implementation is a small file read; honor cancellation in callers.

	raw, err := os.ReadFile(p.procPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.procPath, err)
	}

	parsed := ParseProcModules(string(raw))
	taint := DecodeTaintBits(parseTaintValue(readFileOrEmpty(p.taintPath)))

	now := p.now()
	resolved := make([]LoadedDriver, 0, len(parsed.Drivers))
	for _, d := range parsed.Drivers {
		d.CollectedAt = now
		d.DriverFramework = FrameworkLinuxModule
		d.Architecture = runtime.GOARCH
		d.TaintFlags = taint

		path := p.resolveModulePath(d.Name)
		if path != "" {
			d.Path = path
			info, err := ParseModinfo(path)
			if err == nil {
				applyModinfo(&d, info)
			}
			if hash, err := sha256OfFile(path); err == nil {
				d.OnDiskSHA256 = hash
			}
		}

		if d.SignatureState == "" {
			d.SignatureState = signatureStateFor(d, taint)
		}
		d.CPE23 = software.BuildCPE23WithTargetSW(d.Vendor, d.Name, d.Version, "linux")
		resolved = append(resolved, d)
	}

	parsed.Drivers = resolved
	parsed.Sort()
	return parsed, nil
}

// ParseProcModules parses the kernel-procfs lines:
//
//	name size refcount used_by state address [(LL)]
//
// Per kernel/module/procfs.c. The "used_by" column is "-" when no module
// depends on this one; otherwise it is a comma-separated list with a
// trailing comma. Returns one LoadedDriver per non-empty line.
func ParseProcModules(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		// Minimum: name size refcount used_by state address (6).
		if len(fields) < 6 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "linux-procmodules",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected at least 6 columns (name size refcount used_by state address)"),
			})
			continue
		}

		name := fields[0]
		size, _ := strconv.ParseUint(fields[1], 10, 64)
		_ = size
		refCount := fields[2]
		usedBy := fields[3]
		state := fields[4]

		var deps []string
		if usedBy != "-" {
			for _, dep := range strings.Split(strings.TrimSuffix(usedBy, ","), ",") {
				if dep != "" {
					deps = append(deps, dep)
				}
			}
		}

		drv := LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			Name:            name,
			DriverFramework: FrameworkLinuxModule,
			State:           state,
			StartMode:       "live",
			Dependencies:    deps,
		}
		drv.Description = "loaded kernel module (refcount=" + refCount + ")"
		result.Drivers = append(result.Drivers, drv)
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		result.Errs = append(result.Errs, CollectError{
			Collector: "linux-procmodules",
			Line:      lineNum,
			Err:       err,
		})
	}

	result.Sort()
	return result
}

// resolveModulePath walks /lib/modules/<uname -r> looking for a file whose
// basename matches name + (.ko|.ko.xz|.ko.zst|.ko.gz). Modules with hyphens
// in /proc are stored with underscores on disk and vice versa, so both
// spellings are tried.
func (p *ProcModules) resolveModulePath(name string) string {
	root := p.modulesDir
	if root == "" {
		root = filepath.Join("/lib/modules", uname())
	}
	if root == "" {
		return ""
	}

	candidates := []string{name, strings.ReplaceAll(name, "_", "-"), strings.ReplaceAll(name, "-", "_")}
	exts := []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"}

	wanted := make(map[string]struct{}, len(candidates)*len(exts))
	for _, base := range candidates {
		for _, ext := range exts {
			wanted[base+ext] = struct{}{}
		}
	}

	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir // best-effort traversal
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := wanted[d.Name()]; ok {
			found = path
			return io.EOF // sentinel to stop the walk
		}
		return nil
	})
	return found
}

// uname returns the result of `uname -r` via /proc/sys/kernel/osrelease.
// Empty string when neither is readable.
func uname() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func readFileOrEmpty(path string) string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	return string(data)
}

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path) //#nosec G304 -- path comes from kernel-resolved module paths.
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// applyModinfo copies parsed modinfo keys into the LoadedDriver fields.
func applyModinfo(d *LoadedDriver, info map[string]string) {
	if v, ok := info["version"]; ok {
		d.Version = v
	}
	if v, ok := info["description"]; ok && d.Description != "" {
		d.Description = v
	}
	if v, ok := info["signer"]; ok {
		d.Signer = v
		d.Vendor = strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
	}
	if v, ok := info["sig_hashalgo"]; ok {
		d.SignatureAlgo = v
	}
	if v, ok := info["author"]; ok && d.Vendor == "" {
		d.Vendor = strings.TrimSpace(strings.SplitN(v, "<", 2)[0])
	}
	if v, ok := info["depends"]; ok && v != "" && len(d.Dependencies) == 0 {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				d.Dependencies = append(d.Dependencies, p)
			}
		}
	}
}

// signatureStateFor decides the SignatureState for a Linux module given
// the parsed signer + the global taint vector.
func signatureStateFor(d LoadedDriver, taint []string) string {
	hasFlag := func(letter string) bool {
		for _, t := range taint {
			if t == letter {
				return true
			}
		}
		return false
	}
	if hasFlag("E") {
		// "E" = unsigned module loaded into kernel. The current module may
		// still be signed if it was inserted before; without per-module
		// state we degrade to "unknown" rather than wrongly stamping it.
		if d.Signer != "" {
			return SignatureValid
		}
		return SignatureUnsigned
	}
	if d.Signer != "" {
		return SignatureValid
	}
	return SignatureUnknown
}
