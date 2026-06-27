// nuget.go
package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type NuGet struct{}

func NewNuGet() *NuGet { return &NuGet{} }

func (n *NuGet) Name() string { return "nuget" }

func (n *NuGet) Available() bool {
	_, err := exec.LookPath("dotnet")
	return err == nil
}

func (n *NuGet) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "dotnet", "list", "package", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("dotnet list package: %w", err)
	}
	return ParseNuGetJSON(string(out)), nil
}

type nugetOutput struct {
	Projects []nugetProject `json:"projects"`
}

type nugetProject struct {
	Frameworks []nugetFramework `json:"frameworks"`
}

type nugetFramework struct {
	TopLevelPackages []nugetPackage `json:"topLevelPackages"`
}

type nugetPackage struct {
	ID              string `json:"id"`
	ResolvedVersion string `json:"resolvedVersion"`
}

// ParseNuGetJSON parses the JSON output of dotnet list package --format=json.
func ParseNuGetJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output nugetOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "nuget",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	seen := make(map[string]bool)
	for _, proj := range output.Projects {
		for _, fw := range proj.Frameworks {
			for _, pkg := range fw.TopLevelPackages {
				if pkg.ID == "" {
					continue
				}
				key := pkg.ID + "@" + pkg.ResolvedVersion
				if seen[key] {
					continue
				}
				seen[key] = true

				result.Items = append(result.Items, model.InstalledSoftware{
					ID:             uuid.Must(uuid.NewV7()),
					SoftwareName:   pkg.ID,
					Version:        pkg.ResolvedVersion,
					PackageManager: "nuget",
					CPE23:          BuildCPE23WithTargetSW("", pkg.ID, pkg.ResolvedVersion, ".net"),
				})
			}
		}
	}

	return result
}

var _ Collector = (*NuGet)(nil)
