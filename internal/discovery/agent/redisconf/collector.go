package redisconf

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultPaths is the canonical set of Redis configuration files
// across the major Linux distros + macOS Homebrew. The collector
// also follows `include` directives discovered inside each file, so
// custom layouts ship with config without manual wiring.
func DefaultPaths() []string {
	return []string{
		"/etc/redis/redis.conf",
		"/etc/redis/redis-sentinel.conf",
		"/etc/redis.conf",
		"/etc/redis-sentinel.conf",
		"/usr/local/etc/redis.conf",
		"/usr/local/etc/redis-sentinel.conf",
		"/opt/homebrew/etc/redis.conf",
		"/opt/homebrew/etc/redis-sentinel.conf",
	}
}

// fileCollector parses every redis*.conf reachable from a configured
// seed list — both directly readable files and those they `include`.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	seeds    []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// Redis config paths. Missing files are silently skipped — most
// hosts will only have one or two of the seed paths populated.
func NewLinuxCollector() Collector {
	return &fileCollector{
		seeds:    DefaultPaths(),
		readFile: os.ReadFile,
	}
}

func (c *fileCollector) Name() string { return "redisconf" }

func (c *fileCollector) Collect(_ context.Context) ([]Config, error) {
	visited := make(map[string]struct{})
	out := make([]Config, 0, len(c.seeds))

	var walk func(path string)
	walk = func(path string) {
		cleaned := filepath.Clean(path)
		if _, dup := visited[cleaned]; dup {
			return
		}
		visited[cleaned] = struct{}{}
		body, err := c.readFile(cleaned)
		if err != nil {
			return
		}
		cfg := Parse(body, cleaned)
		out = append(out, cfg)
		// Recurse into includes; they inherit redis.conf's grammar
		// but get their own row so the audit pipeline can attribute
		// findings to the right physical file.
		for _, inc := range cfg.Includes {
			if !strings.HasPrefix(inc, "/") {
				inc = filepath.Join(filepath.Dir(cleaned), inc)
			}
			walk(inc)
		}
	}

	for _, seed := range c.seeds {
		walk(seed)
		if len(out) >= MaxConfigs {
			break
		}
	}

	if len(out) > MaxConfigs {
		out = out[:MaxConfigs]
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FilePath < out[j].FilePath
	})
	return out, nil
}

// ReadFileOrSkipMissing is a tiny wrapper that returns (nil, nil)
// for missing files — useful for callers that want to thread their
// own readFile through fileCollector.
func ReadFileOrSkipMissing(read func(string) ([]byte, error), path string) ([]byte, error) {
	body, err := read(path)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return body, err //nolint:wrapcheck // pass-through helper
}
