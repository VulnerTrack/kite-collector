package driver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// KmutilShowloaded enumerates loaded macOS kernel extensions via
// `kmutil showloaded`. Available on macOS 11+ (Big Sur introduced kmutil).
type KmutilShowloaded struct {
	now    func() time.Time
	binary string
}

// NewKmutilShowloaded constructs a KmutilShowloaded with the kernel-default
// binary path.
func NewKmutilShowloaded() *KmutilShowloaded {
	return &KmutilShowloaded{
		binary: "/usr/bin/kmutil",
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the registry identifier.
func (k *KmutilShowloaded) Name() string { return "darwin-kmutil-showloaded" }

// Available returns true on macOS hosts only.
func (k *KmutilShowloaded) Available() bool { return runtime.GOOS == "darwin" }

// Collect runs kmutil and parses each row into a LoadedDriver.
//
// Invoked as plain `kmutil showloaded`: per kmutil(8) the showloaded
// subcommand accepts --list-only, --no-kernel-components, --sort, etc. —
// there is no --no-symbols option, and kmutil rejects unknown options
// with a usage error and exit status 1.
func (k *KmutilShowloaded) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, k.binary, "showloaded")
	if err != nil {
		return nil, fmt.Errorf("kmutil showloaded: %w", err)
	}
	res := ParseKmutilShowloaded(string(out))
	now := k.now()
	for i := range res.Drivers {
		res.Drivers[i].CollectedAt = now
		res.Drivers[i].Architecture = runtime.GOARCH
		res.Drivers[i].DriverFramework = FrameworkKext
		res.Drivers[i].CPE23 = software.BuildCPE23WithTargetSW(
			res.Drivers[i].Vendor,
			res.Drivers[i].Name,
			res.Drivers[i].Version,
			"macos",
		)
	}
	res.Sort()
	return res, nil
}

// ParseKmutilShowloaded parses the column-aligned output of
// `kmutil showloaded`. Format:
//
//	Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
//
// We extract Index, Name, Version. Real kmutil opens with preamble
// chatter ("No variant specified, falling back to release") before the
// column header; anything ahead of the header that does not lead with a
// numeric Index is skipped as preamble rather than mis-parsed as a row.
func ParseKmutilShowloaded(raw string) *Result {
	res := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNum := 0
	headerSeen := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !headerSeen {
			if strings.HasPrefix(line, "Index Refs") {
				headerSeen = true
				continue
			}
			if !leadsWithIndex(line) {
				continue // preamble chatter, not a kext row
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			res.Errs = append(res.Errs, CollectError{
				Collector: "darwin-kmutil-showloaded",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected at least 6 fields"),
			})
			continue
		}

		// Name and version are joined: "com.apple.driver.AppleAHCIPort (3.4.4)"
		name := fields[5]
		version := ""
		for _, f := range fields[6:] {
			if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
				version = strings.Trim(f, "()")
				break
			}
		}

		res.Drivers = append(res.Drivers, LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			Name:            name,
			Version:         version,
			Vendor:          vendorFromBundleID(name),
			DriverFramework: FrameworkKext,
			State:           "Live",
			StartMode:       "live",
		})
	}
	return res
}

// leadsWithIndex reports whether the line's first whitespace-separated
// field is an unsigned integer — the shape of a kextstat-style row's
// Index column.
func leadsWithIndex(line string) bool {
	f := strings.Fields(line)
	if len(f) == 0 {
		return false
	}
	_, err := strconv.ParseUint(f[0], 10, 64)
	return err == nil
}

// vendorFromBundleID extracts a guessable vendor from a reverse-DNS bundle ID.
//
//	com.apple.driver.AppleAHCIPort -> Apple
//	com.nvidia.GeForce             -> Nvidia
func vendorFromBundleID(bundle string) string {
	parts := strings.Split(bundle, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Title(parts[1]) //nolint:staticcheck // ASCII bundle IDs only
}
