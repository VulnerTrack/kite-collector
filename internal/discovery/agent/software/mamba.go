// mamba.go
package software

import (
	"context"
	"fmt"
	"os/exec"
)

// Mamba collects installed packages using mamba, which produces the same
// JSON format as conda.
type Mamba struct{}

func NewMamba() *Mamba { return &Mamba{} }

func (m *Mamba) Name() string { return "mamba" }

func (m *Mamba) Available() bool {
	_, err := exec.LookPath("mamba")
	return err == nil
}

func (m *Mamba) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "mamba", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("mamba list: %w", err)
	}
	// Reuse conda parser — output format is identical.
	result := ParseCondaJSON(string(out))
	// Relabel items so they are attributed to mamba.
	for i := range result.Items {
		result.Items[i].PackageManager = "mamba"
	}
	for i := range result.Errs {
		result.Errs[i].Collector = "mamba"
	}
	return result, nil
}

var _ Collector = (*Mamba)(nil)
