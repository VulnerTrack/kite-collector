package winsysmon

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

// DefaultConfigPaths is the curated set of Sysmon config locations.
// Sysmon doesn't pin a canonical path — it loads whichever XML the
// operator passed to `Sysmon -c` at install time — but every
// in-the-wild deployment we've seen lands in one of these.
func DefaultConfigPaths() []string {
	return []string{
		`C:\ProgramData\Sysmon\sysmonconfig.xml`,
		`C:\ProgramData\Sysmon\sysmonconfig-export.xml`,
		`C:\ProgramData\Sysmon\config.xml`,
		`C:\Sysmon\sysmonconfig.xml`,
		`C:\Sysmon\config.xml`,
		`C:\Program Files\Sysmon\sysmonconfig.xml`,
		`C:\Windows\Sysmon\sysmonconfig.xml`,
	}
}

// fileCollector reads the first available config from a seed list.
// Test seam swaps `paths` and `readFile`.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	paths    []string
}

// NewCollector returns a Collector wired to the canonical Sysmon
// config paths. On hosts with no Sysmon install (or no on-disk
// XML), Collect returns State{Source: SourceNoConfig}.
func NewCollector() Collector {
	return &fileCollector{
		paths:    DefaultConfigPaths(),
		readFile: os.ReadFile,
	}
}

func (c *fileCollector) Name() string { return "winsysmon" }

func (c *fileCollector) Collect(_ context.Context) (State, error) {
	for _, p := range c.paths {
		body, err := c.readFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return State{Source: SourceUnknown, ConfigPath: p}, err
		}
		state, perr := ParseConfigXML(body)
		if perr != nil {
			return State{Source: SourceUnknown, ConfigPath: p}, perr
		}
		state.Source = SourceConfigXML
		state.ConfigPath = p
		state.FileHash = HashContents(body)
		return state, nil
	}
	return State{Source: SourceNoConfig}, nil
}
