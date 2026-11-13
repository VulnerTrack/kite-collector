package software

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Dpkg collects installed packages using dpkg-query on Debian-based systems.
type Dpkg struct{}

// Keep ${Package}: switching to binary:Package would change inventory keys for
// multiarch packages. source:Version can differ from the binary's version.
const dpkgFormat = "${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Homepage}\t${binary:Summary}\t${db:Status-Status}\n"

// NewDpkg returns a new Dpkg collector.
func NewDpkg() *Dpkg { return &Dpkg{} }

// Name returns the stable identifier for this collector.
func (d *Dpkg) Name() string { return "dpkg" }

// Available reports whether dpkg-query is on the PATH.
func (d *Dpkg) Available() bool {
	_, err := exec.LookPath("dpkg-query")
	return err == nil
}

// Collect runs dpkg-query and returns parsed results. Output is capped at
// 64 MB and the command is killed after 60 seconds.
func (d *Dpkg) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "dpkg-query", "-W", "-f="+dpkgFormat)
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return ParseDpkgOutput(string(out)), nil
}

// ParseDpkgOutput accepts both the legacy three-column output and dpkgFormat.
func ParseDpkgOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "dpkg",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package\\tversion[\\tarch]' format"),
			})
			continue
		}

		arch := ""
		if len(parts) >= 3 {
			arch = parts[2]
		}
		// dpkg -W also lists removed packages with residual configuration.
		if len(parts) >= 8 && parts[len(parts)-1] != "installed" {
			continue
		}
		field := func(i int) string {
			if i < len(parts) {
				return parts[i]
			}
			return ""
		}
		description := field(6)
		if len(parts) >= 8 {
			description = strings.Join(parts[6:len(parts)-1], "\t")
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   parts[0],
			Version:        parts[1],
			PackageManager: "dpkg",
			Architecture:   arch,
			SourcePackage:  field(3),
			SourceVersion:  field(4),
			Homepage:       field(5),
			Description:    description,
			CPE23:          BuildCPE23WithArch("", parts[0], parts[1], arch),
		})
	}
	if err := scanner.Err(); err != nil {
		result.Errs = append(result.Errs, CollectError{Collector: "dpkg", Line: lineNum, Err: err})
	}

	result.Sort()
	return result
}

// Compile-time interface check.
var _ Collector = (*Dpkg)(nil)
