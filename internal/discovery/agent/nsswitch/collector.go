package nsswitch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// fileCollector reads /etc/nsswitch.conf. The file has no drop-in
// convention on mainstream distros — every change goes through that
// single file. macOS doesn't ship a meaningful nsswitch.conf;
// Windows has none at all. Both return empty.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	mainFile string
}

// NewCollector returns the default nsswitch.conf walker.
func NewCollector() Collector {
	return &fileCollector{
		mainFile: "/etc/nsswitch.conf",
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
	}
}

func (c *fileCollector) Name() string { return "nsswitch-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	data, err := c.readFile(c.mainFile)
	if err != nil {
		slog.Debug("nsswitch: main file unreadable",
			"path", c.mainFile, "error", err)
		return nil, nil //nolint:nilerr // empty result on unreadable file
	}
	out := Parse(data, c.mainFile)
	SortEntries(out)
	return out, nil
}
