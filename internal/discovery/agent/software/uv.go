package software

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Uv collects globally installed Python tools managed by uv (`uv tool
// install`), the astral.sh package manager. It is the uv analogue of the Pipx
// collector: `uv tool list` enumerates the installed CLI tools, one per line
// as "<name> v<version>", each followed by indented "- <entrypoint>" lines.
type Uv struct{}

// NewUv returns a new uv tool collector.
func NewUv() *Uv { return &Uv{} }

// Name returns the stable identifier for this collector.
func (u *Uv) Name() string { return "uv" }

// Available reports whether uv is on the PATH.
func (u *Uv) Available() bool {
	_, err := exec.LookPath("uv")
	return err == nil
}

// Collect runs `uv tool list` and returns parsed results. uv has no JSON
// output for this command, so the human-readable listing is parsed.
func (u *Uv) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "uv", "tool", "list")
	if err != nil {
		return nil, fmt.Errorf("uv tool list: %w", err)
	}
	return ParseUvToolList(string(out)), nil
}

// ParseUvToolList parses `uv tool list` output. Tool lines are "<name>
// v<version>"; indented "- <entrypoint>" lines and status messages such as
// "No tools installed." are skipped.
func ParseUvToolList(raw string) *Result {
	result := &Result{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "-") {
			continue // blank or an entrypoint line
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !isUvVersion(fields[1]) {
			continue // status message, not a "<name> v<version>" tool line
		}
		name := fields[0]
		version := strings.TrimPrefix(fields[1], "v")
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "uv",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "python"),
		})
	}
	result.Sort()
	return result
}

// isUvVersion reports whether tok is a uv version token: a leading 'v'
// immediately followed by a digit (e.g. "v1.9.4"). This distinguishes a
// tool's version column from words in a status line like "No tools installed."
func isUvVersion(tok string) bool {
	return len(tok) >= 2 && tok[0] == 'v' && tok[1] >= '0' && tok[1] <= '9'
}

// Compile-time interface check.
var _ Collector = (*Uv)(nil)
