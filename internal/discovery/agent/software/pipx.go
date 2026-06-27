package software

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// pipxStderrLogMax caps the truncated stderr surfaced in the diagnostic
// Warn record. Operators should see enough text to act ("pipx reinstall-all")
// without flooding the journal.
const pipxStderrLogMax = 512

// Pipx collects installed Python CLI tools using pipx.
type Pipx struct{}

// NewPipx returns a new Pipx collector.
func NewPipx() *Pipx { return &Pipx{} }

// Name returns the stable identifier for this collector.
func (p *Pipx) Name() string { return "pipx" }

// Available reports whether pipx is on the PATH.
func (p *Pipx) Available() bool {
	_, err := exec.LookPath("pipx")
	return err == nil
}

// Collect runs pipx list --json and returns parsed results.
//
// pipx exits 1 in two distinct conditions: (a) no venvs installed at all
// (benign empty inventory), and (b) some venvs reference a Python
// interpreter that no longer exists, in which case pipx hides them from
// JSON output and prints diagnostic warnings to stderr. Case (b) is a
// silent data loss the operator needs to know about, so we surface the
// stderr summary as a Warn record with an actionable hint.
func (p *Pipx) Collect(ctx context.Context) (*Result, error) {
	out, stderr, exitCode, err := runWithLimitsTolerateExit(ctx, "pipx", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("pipx list --json: %w", err)
	}
	if exitCode != 0 && len(stderr) > 0 {
		logPipxDiagnostic(exitCode, stderr)
	}
	if exitCode != 0 && len(out) == 0 {
		return &Result{}, nil
	}
	return ParsePipxJSON(string(out)), nil
}

// logPipxDiagnostic emits a single Warn record summarising pipx's stderr
// when it exits non-zero with output. Truncates to pipxStderrLogMax chars
// and appends an actionable hint when the stderr matches the well-known
// "broken interpreter" signature.
func logPipxDiagnostic(exitCode int, stderr []byte) {
	msg := strings.TrimSpace(string(stderr))
	if len(msg) > pipxStderrLogMax {
		msg = msg[:pipxStderrLogMax] + "…"
	}
	hint := ""
	if strings.Contains(string(stderr), "invalid interpreter") ||
		strings.Contains(string(stderr), "missing python interpreter") {
		hint = "pipx may have hidden broken venvs; run `pipx reinstall-all`"
	}
	slog.Warn("software: pipx reported diagnostic on non-zero exit",
		"exit_code", exitCode,
		"stderr", msg,
		"hint", hint,
	)
}

// pipxOutput represents the top-level JSON from pipx list --json.
type pipxOutput struct {
	Venvs map[string]pipxVenv `json:"venvs"`
}

type pipxVenv struct {
	Metadata pipxMetadata `json:"metadata"`
}

type pipxMetadata struct {
	MainPackage pipxMainPackage `json:"main_package"`
}

type pipxMainPackage struct {
	Package        string `json:"package"`
	PackageVersion string `json:"package_version"`
}

// ParsePipxJSON parses the JSON output of pipx list --json.
func ParsePipxJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output pipxOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "pipx",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, venv := range output.Venvs {
		pkg := venv.Metadata.MainPackage
		if pkg.Package == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   pkg.Package,
			Version:        pkg.PackageVersion,
			PackageManager: "pipx",
			CPE23:          BuildCPE23WithTargetSW("", pkg.Package, pkg.PackageVersion, "python"),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Pipx)(nil)
