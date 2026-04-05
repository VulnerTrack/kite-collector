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

// NewDpkg returns a new Dpkg collector.
func NewDpkg() *Dpkg { return &Dpkg{} }

// Name returns the stable identifier for this collector.
func (d *Dpkg) Name() string { return "dpkg" }

// Available reports whether dpkg-query is on the PATH.
func (d *Dpkg) Available() bool {
	_, err := exec.LookPath("dpkg-query")
	return err == nil
}

// Collect runs dpkg-query and returns parsed results.
func (d *Dpkg) Collect(ctx context.Context) (*Result, error) {
	out, err := exec.CommandContext(ctx,
		"dpkg-query", "-W", "-f=${Package}\t${Version}\n",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return ParseDpkgOutput(string(out)), nil
}

// ParseDpkgOutput parses the raw output of dpkg-query -W -f='${Package}\t${Version}\n'.
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

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "dpkg",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package\\tversion' format"),
			})
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   parts[0],
			Version:        parts[1],
			PackageManager: "dpkg",
			CPE23:          BuildCPE23("", parts[0], parts[1]),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Dpkg)(nil)
