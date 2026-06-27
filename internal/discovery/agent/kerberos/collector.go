package kerberos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads /etc/krb5.conf + every drop-in under
// /etc/krb5.conf.d/. macOS uses the same paths; Windows uses AD
// APIs we don't cover here.
type fileCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	mainFile  string
	dropInDir string
}

// NewCollector returns the default krb5.conf file walker.
func NewCollector() Collector {
	return &fileCollector{
		mainFile:  "/etc/krb5.conf",
		dropInDir: "/etc/krb5.conf.d",
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "kerberos-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Setting, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Setting

	if data, err := c.readFile(c.mainFile); err == nil {
		out = append(out, Parse(data, c.mainFile)...)
	} else {
		slog.Debug("kerberos: main file unreadable",
			"path", c.mainFile, "error", err)
	}

	for _, p := range c.lexicalFiles(c.dropInDir) {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, Parse(data, p)...)
		if len(out) >= MaxSettings {
			break
		}
	}

	if len(out) > MaxSettings {
		out = out[:MaxSettings]
	}
	SortSettings(out)
	return out, nil
}

// lexicalFiles returns absolute paths of regular files in `dir`,
// lexically sorted. Backup/swap files are filtered out.
func (c *fileCollector) lexicalFiles(dir string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") ||
			strings.HasSuffix(name, "~") ||
			strings.HasSuffix(name, ".bak") ||
			strings.HasSuffix(name, ".dpkg-old") ||
			strings.HasSuffix(name, ".dpkg-new") ||
			strings.HasSuffix(name, ".rpmsave") ||
			strings.HasSuffix(name, ".swp") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(dir, n))
	}
	return out
}
