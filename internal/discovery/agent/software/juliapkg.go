// juliapkg.go
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

type JuliaPkg struct{}

func NewJuliaPkg() *JuliaPkg { return &JuliaPkg{} }

func (j *JuliaPkg) Name() string { return "juliapkg" }

func (j *JuliaPkg) Available() bool {
	_, err := exec.LookPath("julia")
	return err == nil
}

func (j *JuliaPkg) Collect(ctx context.Context) (*Result, error) {
	script := `using Pkg; foreach(p->println(p.second.name," ",p.second.version),Pkg.dependencies())`
	out, err := runWithLimits(ctx, "julia", "-e", script)
	if err != nil {
		return nil, fmt.Errorf("julia Pkg.dependencies: %w", err)
	}
	return ParseJuliaPkgOutput(string(out)), nil
}

// ParseJuliaPkgOutput parses "name version" lines from Julia Pkg output.
func ParseJuliaPkgOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		idx := strings.LastIndex(line, " ")
		if idx <= 0 || idx >= len(line)-1 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "juliapkg",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name version' format"),
			})
			continue
		}

		name := line[:idx]
		version := line[idx+1:]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "juliapkg",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "julia"),
		})
	}

	return result
}

var _ Collector = (*JuliaPkg)(nil)
