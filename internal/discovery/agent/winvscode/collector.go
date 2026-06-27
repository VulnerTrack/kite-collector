package winvscode

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUsersBases is the curated set of per-OS user-profile
// bases. The collector walks each base, then each user's
// .vscode / .vscode-insiders / .cursor subdir.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// EditorDirs is the curated set of (relative-dir, EditorKind)
// pairs we walk under each user profile.
func EditorDirs() []struct {
	Rel  string
	Kind EditorKind
} {
	return []struct {
		Rel  string
		Kind EditorKind
	}{
		{filepath.Join(".vscode", "extensions"), EditorVSCode},
		{filepath.Join(".vscode-insiders", "extensions"), EditorVSCodeInsiders},
		{filepath.Join(".cursor", "extensions"), EditorCursor},
	}
}

// fileCollector walks editor-extension directories from a
// configurable users-base list. Test seam swaps readFile /
// readDir.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	usersBases []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS user-profile bases. Missing bases / subdirs are silently
// skipped (typical on hosts where the editor isn't installed).
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winvscode" }

func (c *fileCollector) Collect(_ context.Context) ([]Extension, error) {
	out := make([]Extension, 0, 64)
	for _, base := range c.usersBases {
		users, err := c.readDir(base)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		sort.Slice(users, func(i, j int) bool {
			return users[i].Name() < users[j].Name()
		})
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			user := u.Name()
			if isSystemPseudoProfile(user) || strings.HasPrefix(user, ".") {
				continue
			}
			for _, e := range EditorDirs() {
				root := filepath.Join(base, user, e.Rel)
				c.harvestEditorRoot(root, e.Kind, user, &out)
				if len(out) >= MaxExtensions {
					break
				}
			}
			if len(out) >= MaxExtensions {
				break
			}
		}
		if len(out) >= MaxExtensions {
			break
		}
	}
	SortExtensions(out)
	return out, nil
}

// harvestEditorRoot walks one editor's extensions/ directory and
// parses each `<publisher>.<name>-<version>/package.json`.
func (c *fileCollector) harvestEditorRoot(root string, kind EditorKind, user string, out *[]Extension) {
	entries, err := c.readDir(root)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(root, name)
		manifest := filepath.Join(dir, "package.json")
		body, err := c.readFile(manifest)
		if err != nil {
			continue
		}
		ext, err := ParseManifest(body)
		if err != nil {
			continue
		}
		ext.FilePath = manifest
		ext.FileHash = HashContents(body)
		ext.ExtensionDir = dir
		ext.EditorKind = kind
		ext.UserProfile = user
		// Fall back on the directory name when the manifest is
		// missing identity fields.
		if ext.Publisher == "" || ext.ExtensionName == "" {
			pub, n := dirIDComponents(name)
			if ext.Publisher == "" {
				ext.Publisher = pub
			}
			if ext.ExtensionName == "" {
				ext.ExtensionName = n
			}
		}
		AnnotateSecurity(&ext)
		*out = append(*out, ext)
		if len(*out) >= MaxExtensions {
			return
		}
	}
}

// dirIDComponents pulls `(publisher, name)` out of the canonical
// `<publisher>.<name>-<version>` directory name. The
// `<version>` suffix is the trailing dash-separated SemVer; we
// strip it from the right and the leading `.` separates publisher
// from name.
func dirIDComponents(dir string) (string, string) {
	// Strip version suffix (last `-` + remainder).
	id := dir
	if i := strings.LastIndexByte(id, '-'); i > 0 {
		id = id[:i]
	}
	pub, name := ParsePublisherAndName(id)
	return pub, name
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
