// luarocks.go
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

type LuaRocks struct{}

func NewLuaRocks() *LuaRocks { return &LuaRocks{} }

func (l *LuaRocks) Name() string { return "luarocks" }

func (l *LuaRocks) Available() bool {
	_, err := exec.LookPath("luarocks")
	return err == nil
}

func (l *LuaRocks) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "luarocks", "list", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("luarocks list: %w", err)
	}
	return ParseLuaRocksOutput(string(out)), nil
}

// ParseLuaRocksOutput parses the output of luarocks list --porcelain.
// Each line is "name\tversion\tinstalled\trepo".
func ParseLuaRocksOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "luarocks",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name\\tversion\\t...' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "luarocks",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "lua"),
		})
	}

	return result
}

var _ Collector = (*LuaRocks)(nil)
