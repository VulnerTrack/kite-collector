package driver

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// PnPUtilDrivers enumerates third-party Windows drivers via `pnputil`.
// Available on every modern Windows host (built into Windows 10+).
type PnPUtilDrivers struct {
	now         func() time.Time
	pnputilPath string // overridable for tests
}

// NewPnPUtilDrivers constructs a PnPUtilDrivers using the system pnputil.
func NewPnPUtilDrivers() *PnPUtilDrivers {
	return &PnPUtilDrivers{
		pnputilPath: "pnputil.exe",
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the registry identifier.
func (p *PnPUtilDrivers) Name() string { return "windows-pnputil" }

// Available reports whether pnputil is the right collector for this host.
func (p *PnPUtilDrivers) Available() bool { return runtime.GOOS == "windows" }

// Collect runs `pnputil /enum-drivers /format CSV` and parses the rows.
func (p *PnPUtilDrivers) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, p.pnputilPath, "/enum-drivers", "/format", "CSV")
	if err != nil {
		return nil, fmt.Errorf("pnputil: %w", err)
	}
	rows, errs := ParsePnPUtilCSV(string(out))
	res := &Result{Errs: errs}
	now := p.now()
	for _, row := range rows {
		drv := LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			CollectedAt:     now,
			Name:            row.OriginalName,
			DisplayName:     row.OriginalName,
			Path:            row.PublishedName,
			Vendor:          row.Provider,
			Version:         row.Version,
			Description:     row.ClassName,
			DriverFramework: FrameworkWDM,
			SignatureState:  signatureStateFromPnPUtil(row),
			Signer:          row.Signer,
			Architecture:    runtime.GOARCH,
			CPE23:           software.BuildCPE23WithTargetSW(row.Provider, row.OriginalName, row.Version, "windows"),
		}
		res.Drivers = append(res.Drivers, drv)
	}
	res.Sort()
	return res, nil
}

// PnPUtilRow models the columns emitted by `pnputil /enum-drivers /format CSV`.
type PnPUtilRow struct {
	PublishedName string
	OriginalName  string
	Provider      string
	ClassName     string
	ClassGUID     string
	Version       string
	Signer        string
}

// ParsePnPUtilCSV reads the CSV output and returns one PnPUtilRow per data
// row (skips the header). Tolerates missing/extra columns gracefully.
func ParsePnPUtilCSV(raw string) ([]PnPUtilRow, []CollectError) {
	r := csv.NewReader(strings.NewReader(raw))
	r.FieldsPerRecord = -1 // pnputil sometimes emits trailing empty fields
	r.LazyQuotes = true

	var rows []PnPUtilRow
	var errs []CollectError
	header, err := r.Read()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, []CollectError{{Collector: "windows-pnputil", Err: err}}
	}

	idx := indexHeaders(header)
	lineNum := 1
	for {
		rec, err := r.Read()
		lineNum++
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, CollectError{
				Collector: "windows-pnputil",
				Line:      lineNum,
				Err:       err,
			})
			continue
		}

		row := PnPUtilRow{
			PublishedName: pickField(rec, idx, "Published Name"),
			OriginalName:  pickField(rec, idx, "Original Name"),
			Provider:      pickField(rec, idx, "Provider Name"),
			ClassName:     pickField(rec, idx, "Class Name"),
			ClassGUID:     pickField(rec, idx, "Class GUID"),
			Version:       pickField(rec, idx, "Driver Version"),
			Signer:        pickField(rec, idx, "Signer Name"),
		}
		rows = append(rows, row)
	}
	return rows, errs
}

func indexHeaders(headers []string) map[string]int {
	idx := make(map[string]int, len(headers))
	for i, h := range headers {
		idx[strings.TrimSpace(h)] = i
	}
	return idx
}

func pickField(rec []string, idx map[string]int, key string) string {
	pos, ok := idx[key]
	if !ok || pos >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[pos])
}

func signatureStateFromPnPUtil(r PnPUtilRow) string {
	if r.Signer == "" {
		return SignatureUnknown
	}
	if strings.Contains(strings.ToLower(r.Signer), "microsoft windows hardware compatibility publisher") {
		return SignatureValid
	}
	return SignatureValid
}
