package winhosts

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

// DefaultHostsPaths is the canonical hosts-file location for each
// supported OS. The collector tries every path and parses the first
// one it can read — almost every host only has one populated.
func DefaultHostsPaths() []string {
	return []string{
		`C:\Windows\System32\drivers\etc\hosts`,
		"/etc/hosts",
	}
}

// fileCollector walks hosts files from a configurable seed list.
// Test seam swaps `paths` and `readFile`.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	paths    []string
}

// NewCollector returns a Collector wired to the canonical hosts
// paths. Missing files are silently skipped — typical for OSes
// where only one of the paths applies.
func NewCollector() Collector {
	return &fileCollector{
		paths:    DefaultHostsPaths(),
		readFile: os.ReadFile,
	}
}

func (c *fileCollector) Name() string { return "winhosts" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 16)
	for _, p := range c.paths {
		body, err := c.readFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, Parse(body, p)...)
		if len(out) >= MaxEntries {
			break
		}
	}
	if len(out) > MaxEntries {
		out = out[:MaxEntries]
	}
	SortEntries(out)
	return out, nil
}
