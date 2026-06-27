// cran.go
package software

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type CRAN struct{}

func NewCRAN() *CRAN { return &CRAN{} }

func (c *CRAN) Name() string { return "cran" }

func (c *CRAN) Available() bool {
	_, err := exec.LookPath("Rscript")
	return err == nil
}

func (c *CRAN) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "Rscript", "-e",
		`write.csv(installed.packages()[,c("Package","Version")])`)
	if err != nil {
		return nil, fmt.Errorf("rscript installed.packages: %w", err)
	}
	return ParseCRANOutput(string(out)), nil
}

// ParseCRANOutput parses CSV output of R's installed.packages().
// Format: "","Package","Version" header, then "rownum","name","version".
func ParseCRANOutput(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	reader := csv.NewReader(bufio.NewReader(strings.NewReader(raw)))
	records, err := reader.ReadAll()
	if err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "cran",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("csv parse: %w", err),
		})
		return result
	}

	for i, record := range records {
		if i == 0 {
			continue // skip header
		}
		if len(record) < 3 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cran",
				Line:      i + 1,
				RawLine:   strings.Join(record, ","),
				Err:       fmt.Errorf("expected 3 CSV fields, got %d", len(record)),
			})
			continue
		}

		name := record[1]
		version := record[2]

		if name == "" || name == "Package" {
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cran",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "r"),
		})
	}

	return result
}

var _ Collector = (*CRAN)(nil)
