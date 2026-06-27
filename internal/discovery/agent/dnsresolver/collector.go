package dnsresolver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads every known DNS-config file: /etc/resolv.conf,
// /etc/systemd/resolved.conf, any drop-in under
// /etc/systemd/resolved.conf.d/, every NetworkManager keyfile under
// /etc/NetworkManager/system-connections/, and /etc/dnsmasq.conf with
// drop-ins under /etc/dnsmasq.d/.
//
// macOS uses /etc/resolv.conf too (synthesised by configd) so the same
// resolv.conf walker captures it. Windows has no equivalent files; the
// collector returns empty there (Get-DnsClientServerAddress would
// require a separate Windows-only collector — future iteration).
type fileCollector struct {
	readFile         func(string) ([]byte, error)
	readDir          func(string) ([]os.DirEntry, error)
	resolvConf       string
	resolvedConf     string
	resolvedConfDir  string
	nmConnectionsDir string
	dnsmasqConf      string
	dnsmasqConfDir   string
}

// NewCollector returns the default DNS-config file walker.
func NewCollector() Collector {
	return &fileCollector{
		resolvConf:       "/etc/resolv.conf",
		resolvedConf:     "/etc/systemd/resolved.conf",
		resolvedConfDir:  "/etc/systemd/resolved.conf.d",
		nmConnectionsDir: "/etc/NetworkManager/system-connections",
		dnsmasqConf:      "/etc/dnsmasq.conf",
		dnsmasqConfDir:   "/etc/dnsmasq.d",
		readFile:         func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:          func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "dns-resolver-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Resolver, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Resolver

	// /etc/resolv.conf
	if data, err := c.readFile(c.resolvConf); err == nil {
		out = append(out, ParseResolvConf(data, c.resolvConf)...)
	} else {
		slog.Debug("dnsresolver: resolv.conf unreadable",
			"path", c.resolvConf, "error", err)
	}

	// /etc/systemd/resolved.conf + drop-ins.
	if data, err := c.readFile(c.resolvedConf); err == nil {
		out = append(out, ParseSystemdResolvedConf(data, c.resolvedConf)...)
	}
	for _, p := range c.lexicalFiles(c.resolvedConfDir, ".conf") {
		if data, err := c.readFile(p); err == nil {
			out = append(out, ParseSystemdResolvedConf(data, p)...)
		}
	}

	// NetworkManager keyfiles. Conventionally chmod 0600 and root-owned;
	// when readable we get the same data resolved.conf would propagate.
	for _, p := range c.lexicalFiles(c.nmConnectionsDir, ".nmconnection") {
		if data, err := c.readFile(p); err == nil {
			out = append(out, ParseNetworkManagerKeyfile(data, p)...)
		}
	}

	// dnsmasq main + drop-ins.
	if data, err := c.readFile(c.dnsmasqConf); err == nil {
		out = append(out, ParseDnsmasqConf(data, c.dnsmasqConf)...)
	}
	for _, p := range c.lexicalFiles(c.dnsmasqConfDir, ".conf") {
		if data, err := c.readFile(p); err == nil {
			out = append(out, ParseDnsmasqConf(data, p)...)
		}
	}

	if len(out) > MaxResolvers {
		out = out[:MaxResolvers]
	}
	SortResolvers(out)
	return out, nil
}

// lexicalFiles returns the absolute paths of files in `dir` whose
// name ends with `suffix`. The result is lexically sorted so the
// scan order (and therefore audit diff output) is stable.
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
