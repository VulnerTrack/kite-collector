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

// Kldstat enumerates loaded FreeBSD kernel modules via `kldstat -v`.
// FreeBSD-only.
type Kldstat struct {
	now    func() time.Time
	binary string
}

// NewKldstat constructs a Kldstat with the kernel-default binary path.
func NewKldstat() *Kldstat {
	return &Kldstat{
		binary: "/sbin/kldstat",
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the registry identifier.
func (k *Kldstat) Name() string { return "freebsd-kldstat" }

// Available returns true on FreeBSD hosts only.
func (k *Kldstat) Available() bool { return runtime.GOOS == "freebsd" }

// Collect runs `kldstat -v` and parses the result.
func (k *Kldstat) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, k.binary, "-v")
	if err != nil {
		return nil, fmt.Errorf("kldstat: %w", err)
	}
	res := ParseKldstat(string(out))
	now := k.now()
	for i := range res.Drivers {
		res.Drivers[i].CollectedAt = now
		res.Drivers[i].Architecture = runtime.GOARCH
		res.Drivers[i].DriverFramework = FrameworkKLD
		res.Drivers[i].CPE23 = software.BuildCPE23WithTargetSW(
			res.Drivers[i].Vendor,
			res.Drivers[i].Name,
			res.Drivers[i].Version,
			"freebsd",
		)
	}
	res.Sort()
	return res, nil
}

// ParseKldstat parses lines of the form:
//
//	Id Refs Address                Size Name
//	 1   77 0xffffffff80200000 1c5e3a8 kernel
//	 2    1 0xffffffff81e60000   2e8b8 ums.ko
//
// We extract Id, Refs, and Name. Sub-blocks ("Contains modules:") are
// skipped because they describe internal symbol modules, not loaded files.
func ParseKldstat(raw string) *Result {
	res := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Id ") || strings.HasPrefix(line, "Contains modules") || strings.HasPrefix(line, "Id Name") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			// Sub-rows from "Contains modules" — id name only.
			continue
		}
		// First field must be a numeric id; otherwise treat as garbage.
		if !isAllDigits(fields[0]) {
			res.Errs = append(res.Errs, CollectError{
				Collector: "freebsd-kldstat",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected numeric Id in column 1"),
			})
			continue
		}

		name := fields[4]
		res.Drivers = append(res.Drivers, LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			Name:            name,
			DriverFramework: FrameworkKLD,
			State:           "Live",
			StartMode:       "live",
		})
	}
	return res
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
