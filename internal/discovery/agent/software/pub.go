// pub.go
package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type Pub struct{}

func NewPub() *Pub { return &Pub{} }

func (p *Pub) Name() string { return "pub" }

func (p *Pub) Available() bool {
	_, err := exec.LookPath("dart")
	return err == nil
}

func (p *Pub) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "dart", "pub", "deps", "--json")
	if err != nil {
		return nil, fmt.Errorf("dart pub deps: %w", err)
	}
	return ParsePubJSON(string(out)), nil
}

type pubOutput struct {
	Packages []pubPackage `json:"packages"`
}

type pubPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParsePubJSON parses the JSON output of dart pub deps --json.
func ParsePubJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output pubOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "pub",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, pkg := range output.Packages {
		if pkg.Name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   pkg.Name,
			Version:        pkg.Version,
			PackageManager: "pub",
			CPE23:          BuildCPE23WithTargetSW("", pkg.Name, pkg.Version, "dart"),
		})
	}

	return result
}

var _ Collector = (*Pub)(nil)
