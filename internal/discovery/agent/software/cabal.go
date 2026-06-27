// cabal.go
package software

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type Cabal struct{}

func NewCabal() *Cabal { return &Cabal{} }

func (c *Cabal) Name() string { return "cabal" }

func (c *Cabal) Available() bool {
	_, err := exec.LookPath("ghc-pkg")
	return err == nil
}

func (c *Cabal) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "ghc-pkg", "list", "--simple-output")
	if err != nil {
		return nil, fmt.Errorf("ghc-pkg list: %w", err)
	}
	return ParseCabalOutput(string(out)), nil
}

// ParseCabalOutput parses the output of ghc-pkg list --simple-output.
// Output is space-separated "name-version" tokens.
func ParseCabalOutput(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	tokens := strings.Fields(raw)
	for _, token := range tokens {
		name, version := splitNameVersion(token)
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cabal",
				Line:      1,
				RawLine:   token,
				Err:       errors.New("cannot split package name and version"),
			})
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cabal",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "haskell"),
		})
	}

	return result
}

var _ Collector = (*Cabal)(nil)
