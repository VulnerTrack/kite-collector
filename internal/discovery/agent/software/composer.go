// composer.go
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

type Composer struct{}

func NewComposer() *Composer { return &Composer{} }

func (c *Composer) Name() string { return "composer" }

func (c *Composer) Available() bool {
	_, err := exec.LookPath("composer")
	return err == nil
}

func (c *Composer) Collect(ctx context.Context) (*Result, error) {
	// composer show exits 1 when there is no composer.json in cwd and no
	// global vendor tree. That is a normal "this host has no composer
	// project" state, not a parser failure — return zero items quietly
	// instead of bubbling a parse error up.
	out, _, exitCode, err := runWithLimitsTolerateExit(ctx, "composer", "show", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("composer show: %w", err)
	}
	if exitCode != 0 && len(out) == 0 {
		return &Result{}, nil
	}
	return ParseComposerJSON(string(out)), nil
}

type composerOutput struct {
	Installed []composerPackage `json:"installed"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseComposerJSON parses the JSON output of composer show --format=json.
func ParseComposerJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output composerOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "composer",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, pkg := range output.Installed {
		if pkg.Name == "" {
			continue
		}

		vendor := ""
		product := pkg.Name
		if idx := strings.Index(pkg.Name, "/"); idx > 0 {
			vendor = pkg.Name[:idx]
			product = pkg.Name[idx+1:]
		}

		version := strings.TrimPrefix(pkg.Version, "v")

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   product,
			Vendor:         vendor,
			Version:        version,
			PackageManager: "composer",
			CPE23:          BuildCPE23WithTargetSW(vendor, product, version, "php"),
		})
	}

	return result
}

var _ Collector = (*Composer)(nil)
