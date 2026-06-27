package winscheduledtasks

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultTasksRoot is the canonical on-disk root for Task Scheduler
// task XML files on every modern Windows. The parser doesn't care
// what OS it runs on, so the collector is build-tag-agnostic — on
// non-Windows hosts the root simply doesn't exist and Collect
// returns an empty slice.
const DefaultTasksRoot = `C:\Windows\System32\Tasks`

// fileCollector walks the Tasks directory tree from a configurable
// root. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

// NewCollector returns a Collector wired to the canonical Tasks
// directory. Missing root (non-Windows host) → empty slice.
func NewCollector() Collector {
	return &fileCollector{
		root:     DefaultTasksRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winscheduledtasks" }

func (c *fileCollector) Collect(_ context.Context) ([]Task, error) {
	out := make([]Task, 0, 256)
	var walk func(path string) error
	walk = func(path string) error {
		entries, err := c.readDir(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		// Lexical order for deterministic output across scans.
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			full := filepath.Join(path, name)
			if e.IsDir() {
				if err := walk(full); err != nil {
					return err
				}
				if len(out) >= MaxTasks {
					return nil
				}
				continue
			}
			body, err := c.readFile(full)
			if err != nil {
				continue
			}
			task, err := ParseTaskXML(body, full, taskPathFromFS(c.root, full))
			if err != nil {
				continue
			}
			out = append(out, task)
			if len(out) >= MaxTasks {
				return nil
			}
		}
		return nil
	}
	if err := walk(c.root); err != nil {
		return nil, err
	}
	SortTasks(out)
	return out, nil
}

// taskPathFromFS converts an on-disk path under the Tasks root into
// the logical Task Scheduler path. The root for a file
// `C:\Windows\System32\Tasks\Microsoft\Windows\AppID\PolicyConverter`
// becomes `\Microsoft\Windows\AppID\PolicyConverter`.
func taskPathFromFS(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	rel = filepath.ToSlash(rel)
	rel = strings.ReplaceAll(rel, "/", `\`)
	if !strings.HasPrefix(rel, `\`) {
		rel = `\` + rel
	}
	return rel
}
