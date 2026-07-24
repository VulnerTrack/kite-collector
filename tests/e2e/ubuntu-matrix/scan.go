package ubuntumatrix

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// parseErrorMsg is the fixed slog message the engine emits for every
// non-fatal per-line CollectError. The schema behind it is already gated by
// scripts/check-parse-errors.sh, so counting these lines is a contract-safe
// way to populate PackageDiscoveryTestRun.parse_error_count (§4.1.3).
const parseErrorMsg = "engine: software parse error"

// Package mirrors one model.InstalledSoftware row as it appears in
// `kite-collector scan --output json`. Only the fields RFC-0149 R1 asserts on
// are modelled; the rest of the machine record is intentionally ignored.
type Package struct {
	SoftwareName   string `json:"software_name"`
	Vendor         string `json:"vendor"`
	Version        string `json:"version"`
	CPE23          string `json:"cpe23"`
	PackageManager string `json:"package_manager"`
	Architecture   string `json:"architecture"`
}

// Key identifies one discovered row for diffing purposes.
func (p Package) Key() string {
	return p.SoftwareName + "|" + p.Architecture
}

// scanMachine is the subset of the scan JSON array element we consume.
type scanMachine struct {
	Software []Package `json:"software"`
}

// ParseScanOutput flattens `kite-collector scan --output json` stdout into
// the discovered package list. The scan writes a JSON array of machines to
// stdout and slog records to stderr; this only ever reads stdout.
func ParseScanOutput(stdout []byte) ([]Package, error) {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return nil, errors.New("scan produced no stdout; expected a JSON array of machines")
	}

	var machines []scanMachine
	if err := json.Unmarshal(trimmed, &machines); err != nil {
		return nil, fmt.Errorf("decode scan output: %w", err)
	}

	pkgs := make([]Package, 0, len(machines))
	for _, m := range machines {
		pkgs = append(pkgs, m.Software...)
	}
	return pkgs, nil
}

// FilterByPackageManager narrows a discovered set to one collector's rows.
func FilterByPackageManager(pkgs []Package, manager string) []Package {
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if p.PackageManager == manager {
			out = append(out, p)
		}
	}
	return out
}

// IndexByName groups discovered packages by name. Multi-arch installs put
// several rows under one name, which is exactly the shape the multiarch
// checks need.
func IndexByName(pkgs []Package) map[string][]Package {
	idx := make(map[string][]Package, len(pkgs))
	for _, p := range pkgs {
		idx[p.SoftwareName] = append(idx[p.SoftwareName], p)
	}
	return idx
}

// CountParseErrors counts the engine's per-line software parse-error records
// in captured stderr. Non-JSON lines (the human-readable scan summary) are
// skipped rather than treated as an error.
func CountParseErrors(stderr []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(stderr))
	// dpkg status files can carry very long Description lines; give the
	// scanner room so a long record is not mistaken for end-of-input.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Msg == parseErrorMsg {
			count++
		}
	}
	return count
}
