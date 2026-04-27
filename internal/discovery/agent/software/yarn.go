// yarn.go
package software

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type Yarn struct{}

func NewYarn() *Yarn { return &Yarn{} }

func (y *Yarn) Name() string { return "yarn" }

func (y *Yarn) Available() bool {
	_, err := exec.LookPath("yarn")
	return err == nil
}

func (y *Yarn) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "yarn", "global", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("yarn global list: %w", err)
	}
	return ParseYarnJSON(string(out)), nil
}

// yarnLine is the JSON-line envelope yarn emits. Yarn produces several
// Type values (progressStart/Stop, info, success, etc.) and the Data field
// shape varies per type — info carries a string ("pkg@version"), while
// progressStart carries an object ({id, total}). Decode Data lazily so we
// only try to coerce it when we actually want a string (Type == "info").
type yarnLine struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// ParseYarnJSON parses the JSON-lines output of yarn global list --json.
func ParseYarnJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry yarnLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			result.Errs = append(result.Errs, CollectError{
				Collector: "yarn",
				Line:      lineNum,
				RawLine:   truncateRaw(line),
				Err:       fmt.Errorf("json decode: %w", err),
			})
			continue
		}

		if entry.Type != "info" || len(entry.Data) == 0 {
			continue
		}

		// Only "info" records carry a string Data payload. Anything else
		// (e.g. info with nested objects emitted by some yarn versions)
		// is skipped silently — not every info line is a package row.
		var data string
		if err := json.Unmarshal(entry.Data, &data); err != nil {
			continue
		}
		if data == "" {
			continue
		}

		// Handle scoped packages (@scope/name@version).
		atIdx := strings.LastIndex(data, "@")
		if atIdx <= 0 {
			continue
		}

		name := data[:atIdx]
		version := data[atIdx+1:]

		// Strip "has binaries:" suffix if present.
		if strings.Contains(version, " ") {
			version = strings.Fields(version)[0]
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "yarn",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "node.js"),
		})
	}

	return result
}

var _ Collector = (*Yarn)(nil)
