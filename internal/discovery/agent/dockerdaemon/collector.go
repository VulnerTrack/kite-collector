package dockerdaemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

// DefaultConfigPath is the canonical daemon.json location on Linux.
// macOS / Windows host the docker-desktop config in a per-user path
// that we don't touch here; the dedicated collectors do.
const DefaultConfigPath = "/etc/docker/daemon.json"

// fileCollector walks daemon.json from a configurable path. The
// test seam swaps `readFile` and `configPath`.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	configPath string
}

// NewLinuxCollector returns a Collector that reads
// /etc/docker/daemon.json. On hosts without the file, it returns a
// State{Source: SourceNoConfig} — the audit pipeline distinguishes
// "no probe ran" from "the daemon is using compiled-in defaults".
func NewLinuxCollector() Collector {
	return &fileCollector{
		configPath: DefaultConfigPath,
		readFile:   os.ReadFile,
	}
}

func (c *fileCollector) Name() string { return "dockerdaemon" }

func (c *fileCollector) Collect(_ context.Context) (State, error) {
	body, err := c.readFile(c.configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{Source: SourceNoConfig}, nil
		}
		return State{Source: SourceUnknown}, err
	}
	state, err := ParseDaemonJSON(body)
	if err != nil {
		return State{Source: SourceUnknown, ConfigPath: c.configPath}, err
	}
	state.Source = SourceDaemonJSON
	state.ConfigPath = c.configPath
	state.FileHash = HashContents(body)
	state.RawConfig = string(body)
	AnnotateSecurity(&state)
	SortLists(&state)
	return state, nil
}
