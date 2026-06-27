package pam

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector walks /etc/pam.d/* (one file per service) and the legacy
// /etc/pam.conf (single file with a leading `service` column). macOS ships
// with /etc/pam.d/* too. Windows has no PAM — the collector returns
// empty there.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	pamD     string
	pamConf  string
}

// NewCollector returns the default PAM file walker.
func NewCollector() Collector {
	return &fileCollector{
		pamD:     "/etc/pam.d",
		pamConf:  "/etc/pam.conf",
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "pam-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Directive, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Directive

	// /etc/pam.d/<service> — walked in lexical order for stable diffs.
	entries, err := c.readDir(c.pamD)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !pamIncludesFile(e.Name()) {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(c.pamD, name)
			data, ferr := c.readFile(path)
			if ferr != nil {
				continue
			}
			// In /etc/pam.d/<service>, the service is the file basename.
			out = append(out, Parse(data, name, path)...)
			if len(out) >= MaxDirectives {
				break
			}
		}
	} else {
		slog.Debug("pam: /etc/pam.d unreadable",
			"path", c.pamD, "error", err)
	}

	// Legacy /etc/pam.conf — lines have a leading `service` token we
	// strip before delegating to the same parser.
	if data, err := c.readFile(c.pamConf); err == nil {
		out = append(out, parsePamConf(data, c.pamConf)...)
	} else {
		slog.Debug("pam: /etc/pam.conf unreadable",
			"path", c.pamConf, "error", err)
	}

	if len(out) > MaxDirectives {
		out = out[:MaxDirectives]
	}
	SortDirectives(out)
	return out, nil
}

// parsePamConf adapts /etc/pam.conf (legacy single-file form) by
// splitting off the leading `service` token from every non-comment line
// and re-emitting the remainder as a pam.d-style body for Parse to
// consume. We process each unique service as a separate Parse call so
// the per-service hash mirrors the pam.d behaviour.
func parsePamConf(raw []byte, filePath string) []Directive {
	hash := HashContents(raw)
	lines := splitMergeContinuations(string(raw))

	out := make([]Directive, 0, len(lines))
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		// First token is the service name; rest is a pam.d-style line.
		fields := strings.SplitN(clean, " ", 2)
		if len(fields) < 2 {
			fields = strings.SplitN(clean, "\t", 2)
		}
		if len(fields) < 2 {
			continue
		}
		service := strings.TrimSpace(fields[0])
		body := strings.TrimSpace(fields[1])
		d, ok := parseLine(body)
		if !ok {
			continue
		}
		d.FilePath = filePath
		d.FileHash = hash
		d.LineNo = i + 1
		d.Service = service
		d.RawLine = collapseWhitespace(clean)
		d.IsUnconditionalPass = IsUnconditionalPassModule(d.Module) &&
			(d.Type == TypeAuth || d.Type == TypeAccount)
		d.IsNullok = argsContain(d.Arguments, "nullok")
		d.IsNonstandardPath = !IsStandardModulePath(d.ModulePath)
		d.ShortCircuitsStack = strings.EqualFold(d.Control, "sufficient") &&
			d.IsUnconditionalPass
		out = append(out, d)
		if len(out) >= MaxDirectives {
			break
		}
	}
	return out
}

// pamIncludesFile mirrors what pam_unix's loader treats as a service
// file. PAM itself reads any regular file in /etc/pam.d, but distros
// conventionally leave backups (`.bak`, `.dpkg-old`, `~`) lying around
// and we don't want those polluting the inventory.
func pamIncludesFile(name string) bool {
	if name == "" {
		return false
	}
	if name[0] == '.' {
		return false
	}
	if name[len(name)-1] == '~' {
		return false
	}
	for _, suffix := range []string{
		".bak", ".old", ".dpkg-old", ".dpkg-new", ".dpkg-dist",
		".rpmnew", ".rpmsave", ".swp",
	} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}
