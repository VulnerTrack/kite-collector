// gomod.go
package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type GoMod struct{}

func NewGoMod() *GoMod { return &GoMod{} }

func (g *GoMod) Name() string { return "gomod" }

func (g *GoMod) Available() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

func (g *GoMod) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "go", "list", "-m", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	return ParseGoModJSON(string(out)), nil
}

type goModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Main    bool   `json:"Main"`
}

// ParseGoModJSON parses the streaming JSON output of go list -m -json all.
func ParseGoModJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	lineNum := 0
	for dec.More() {
		lineNum++
		var mod goModule
		if err := dec.Decode(&mod); err != nil {
			result.Errs = append(result.Errs, CollectError{
				Collector: "gomod",
				Line:      lineNum,
				RawLine:   truncateRaw(raw),
				Err:       fmt.Errorf("json decode: %w", err),
			})
			return result
		}

		// Skip the main module (it's the project itself).
		if mod.Main || mod.Path == "" {
			continue
		}

		version := strings.TrimPrefix(mod.Version, "v")

		// Extract vendor from module path (e.g. "github.com/foo/bar" -> "foo").
		vendor := ""
		parts := strings.Split(mod.Path, "/")
		if len(parts) >= 2 {
			vendor = parts[len(parts)-2]
		}

		product := parts[len(parts)-1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   product,
			Vendor:         vendor,
			Version:        version,
			PackageManager: "gomod",
			CPE23:          BuildCPE23WithTargetSW(vendor, product, version, "go"),
		})
	}

	return result
}

var _ Collector = (*GoMod)(nil)
