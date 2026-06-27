package winwer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultArchiveRoot is the canonical ReportArchive directory.
const DefaultArchiveRoot = `C:\ProgramData\Microsoft\Windows\WER\ReportArchive`

// DefaultQueueRoot is the canonical ReportQueue directory.
const DefaultQueueRoot = `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`

// MinidumpExtensions is the curated set of WER minidump file
// extensions. `.dmp` is a process minidump; `.hdmp` is a heap-
// extended minidump; `.mdmp` is the legacy alias.
func MinidumpExtensions() []string {
	return []string{".dmp", ".hdmp", ".mdmp"}
}

// fileCollector walks WER report dirs from a configurable seed
// list. Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	roots    []rootSeed
}

type rootSeed struct {
	path string
	kind ReportKind
}

// NewCollector returns a Collector wired to the canonical WER
// directories. Missing roots are silently skipped (typical on
// non-Windows hosts, fresh installs).
func NewCollector() Collector {
	return &fileCollector{
		roots: []rootSeed{
			{path: DefaultArchiveRoot, kind: KindArchive},
			{path: DefaultQueueRoot, kind: KindQueue},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winwer" }

func (c *fileCollector) Collect(_ context.Context) ([]Report, error) {
	out := make([]Report, 0, 16)
	for _, root := range c.roots {
		dirs, err := c.readDir(root.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		sort.Slice(dirs, func(i, j int) bool {
			return dirs[i].Name() < dirs[j].Name()
		})
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			reportDir := filepath.Join(root.path, name)
			r := c.processReportDir(reportDir, root.kind)
			out = append(out, r)
			if len(out) >= MaxReports {
				break
			}
		}
		if len(out) >= MaxReports {
			break
		}
	}
	SortReports(out)
	return out, nil
}

// processReportDir parses Report.wer + tallies minidump metadata
// inside a single report directory. Always returns a Report —
// even when Report.wer is missing the row still represents the
// directory presence.
func (c *fileCollector) processReportDir(dir string, kind ReportKind) Report {
	r := Report{ReportDir: dir, ReportKind: kind}

	entries, err := c.readDir(dir)
	if err != nil {
		return r
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		full := filepath.Join(dir, name)

		// Report.wer descriptor — parse for app metadata.
		if lower == "report.wer" || lower == "report.wer.tmp" {
			r.ReportDescriptorPath = full
			if body, err := c.readFile(full); err == nil {
				ParseReportDescriptor(body, &r)
			}
			continue
		}

		// Minidump file — count + tally bytes, but DO NOT read
		// the body (it's sensitive and large).
		if isMinidumpExtension(filepath.Ext(name)) {
			r.MinidumpCount++
			if fi, err := c.statFile(full); err == nil {
				r.MinidumpTotalBytes += fi.Size()
			}
		}
	}

	AnnotateSecurity(&r)
	return r
}

// isMinidumpExtension reports whether `ext` is in the curated
// minidump set (case-insensitive).
func isMinidumpExtension(ext string) bool {
	e := strings.ToLower(strings.TrimSpace(ext))
	for _, k := range MinidumpExtensions() {
		if e == k {
			return true
		}
	}
	return false
}
