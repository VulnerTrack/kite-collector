// conda.go
package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type Conda struct{}

func NewConda() *Conda { return &Conda{} }

func (c *Conda) Name() string { return "conda" }

func (c *Conda) Available() bool {
	_, err := exec.LookPath("conda")
	return err == nil
}

func (c *Conda) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "conda", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("conda list: %w", err)
	}
	return ParseCondaJSON(string(out)), nil
}

type condaPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Channel string `json:"channel"`
}

// ParseCondaJSON parses the JSON output of conda list --json.
func ParseCondaJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var packages []condaPackage
	if err := json.Unmarshal([]byte(raw), &packages); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "conda",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   pkg.Name,
			Version:        pkg.Version,
			PackageManager: "conda",
			CPE23:          BuildCPE23WithTargetSW("", pkg.Name, pkg.Version, "python"),
		})
	}

	return result
}

var _ Collector = (*Conda)(nil)
