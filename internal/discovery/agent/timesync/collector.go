package timesync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads every well-known time-sync config file: chrony
// (main + drop-ins), ntpd, systemd-timesyncd (main + drop-ins), and
// OpenNTPD. macOS has /etc/ntp.conf too, captured via the ntpd parser.
// Windows has no equivalent files; a future iteration will cover w32time
// via the registry.
type fileCollector struct {
	readFile      func(string) ([]byte, error)
	readDir       func(string) ([]os.DirEntry, error)
	chronyConf    string
	chronyConfDir string
	ntpdConf      string
	timesyncdConf string
	timesyncdDir  string
	openntpdConf  string
}

// NewCollector returns the default time-sync file walker.
func NewCollector() Collector {
	return &fileCollector{
		chronyConf:    "/etc/chrony/chrony.conf",
		chronyConfDir: "/etc/chrony/conf.d",
		ntpdConf:      "/etc/ntp.conf",
		timesyncdConf: "/etc/systemd/timesyncd.conf",
		timesyncdDir:  "/etc/systemd/timesyncd.conf.d",
		openntpdConf:  "/etc/openntpd/ntpd.conf",
		readFile:      func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:       func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "timesync-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Peer, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Peer

	// chrony main + drop-ins.
	if data, err := c.readFile(c.chronyConf); err == nil {
		out = append(out, ParseChrony(data, c.chronyConf)...)
	}
	for _, p := range c.lexicalFiles(c.chronyConfDir, ".conf") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseChrony(data, p)...)
	}

	// ntpd (also covers macOS /etc/ntp.conf).
	if data, err := c.readFile(c.ntpdConf); err == nil {
		out = append(out, ParseNTPd(data, c.ntpdConf)...)
	}

	// systemd-timesyncd main + drop-ins.
	if data, err := c.readFile(c.timesyncdConf); err == nil {
		out = append(out, ParseTimesyncd(data, c.timesyncdConf)...)
	}
	for _, p := range c.lexicalFiles(c.timesyncdDir, ".conf") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseTimesyncd(data, p)...)
	}

	// OpenNTPD.
	if data, err := c.readFile(c.openntpdConf); err == nil {
		out = append(out, ParseOpenNTPd(data, c.openntpdConf)...)
	}

	if len(out) > MaxPeers {
		out = out[:MaxPeers]
	}
	SortPeers(out)
	return out, nil
}

// lexicalFiles returns the absolute paths of files in `dir` whose
// name ends with `suffix`, lexically sorted for stable diff output.
func (c *fileCollector) lexicalFiles(dir, suffix string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(dir, n))
	}
	return out
}
