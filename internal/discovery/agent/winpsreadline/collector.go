package winpsreadline

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUsersBase is the parent of every local user profile.
const DefaultUsersBase = `C:\Users`

// HistoryRelComponents is the per-user relative path components
// under each profile where PSReadLine writes its history. Kept as
// a slice so filepath.Join produces the right separator on every
// OS — `\` on Windows, `/` on Linux/macOS test runners.
var HistoryRelComponents = []string{
	"AppData", "Roaming", "Microsoft", "Windows",
	"PowerShell", "PSReadLine", "ConsoleHost_history.txt",
}

// fileCollector walks per-user history files from a configurable
// users base. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	usersBase string
}

// NewCollector returns a Collector wired to the canonical Users
// base. Missing users base or missing history files are silently
// skipped.
func NewCollector() Collector {
	return &fileCollector{
		usersBase: DefaultUsersBase,
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winpsreadline" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 64)

	entries, err := c.readDir(c.usersBase)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
			continue
		}
		history := filepath.Join(append(
			[]string{c.usersBase, name}, HistoryRelComponents...,
		)...)
		body, err := c.readFile(history)
		if err != nil {
			continue
		}
		hash := HashContents(body)
		c.scanHistory(body, history, hash, name, &out)
		if len(out) >= MaxLines {
			break
		}
	}

	SortEntries(out)
	return out, nil
}

// scanHistory walks one history file body line-by-line, emits an
// Entry for every line that matches at least one curated pattern.
func (c *fileCollector) scanHistory(body []byte, path, hash, user string, out *[]Entry) {
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	lineNo := 0
	for scan.Scan() {
		lineNo++
		line := scan.Text()
		if IsCommentOrBlank(line) {
			continue
		}
		kind := ClassifyLine(line)
		if kind == KindUnknown {
			continue
		}
		e := Entry{
			FilePath:    path,
			FileHash:    hash,
			UserProfile: user,
			LineNo:      lineNo,
			Command:     strings.TrimRight(line, "\r"),
			FindingKind: kind,
		}
		AnnotateSecurity(&e)
		*out = append(*out, e)
		if len(*out) >= MaxLines {
			return
		}
	}
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
