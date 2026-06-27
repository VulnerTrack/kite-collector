package driver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// KmutilShowloaded enumerates loaded macOS kernel extensions via
// `kmutil showloaded --no-symbols`. Available on macOS 10.15+.
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
func (k *KmutilShowloaded) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, k.binary, "showloaded", "--no-symbols")
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
// `kmutil showloaded --no-symbols`. Format:
//
//	Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
//
// We extract Index, Name, Version. The fixed-column header is detected and
// skipped; everything else is treated as a row.
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
		if !headerSeen && strings.HasPrefix(line, "Index Refs") {
			headerSeen = true
			continue
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
