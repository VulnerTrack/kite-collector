package mongodconf

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

// DefaultConfigPaths is the canonical set of mongod.conf locations.
// The collector picks the first readable path; mongod processes are
// singletons per host in practice.
func DefaultConfigPaths() []string {
	return []string{
		"/etc/mongod.conf",
		"/etc/mongodb.conf",
		"/usr/local/etc/mongod.conf",
		"/opt/homebrew/etc/mongod.conf",
	}
}

// fileCollector reads the first available mongod.conf from a seed
// list and parses it. Test seam swaps `readFile` and `paths`.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	paths    []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// mongod.conf paths. On hosts with no mongod, it returns a
// State{Source: SourceNoConfig}.
func NewLinuxCollector() Collector {
	return &fileCollector{
		paths:    DefaultConfigPaths(),
		readFile: os.ReadFile,
	}
}

func (c *fileCollector) Name() string { return "mongodconf" }

func (c *fileCollector) Collect(_ context.Context) (State, error) {
	for _, p := range c.paths {
		body, err := c.readFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return State{Source: SourceUnknown, ConfigPath: p}, err
		}
		state, perr := ParseConfig(body)
		if perr != nil {
			return State{Source: SourceUnknown, ConfigPath: p}, perr
		}
		state.Source = SourceConfigYAML
		state.ConfigPath = p
		state.FileHash = HashContents(body)
		AnnotateSecurity(&state)
		SortBindIPs(&state)
		return state, nil
	}
	return State{Source: SourceNoConfig}, nil
}
