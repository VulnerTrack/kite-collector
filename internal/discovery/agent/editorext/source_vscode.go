package editorext

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// vscodeCollector walks every known VS Code-family editor's extension
// directory and parses each extension's package.json. All VS Code forks
// share the same on-disk layout (it's the same Electron codebase):
//
//	~/.vscode/extensions/<publisher>.<name>-<version>/package.json
//	~/.cursor/extensions/<publisher>.<name>-<version>/package.json
//	~/.vscode-server/extensions/...   (Remote-SSH installations)
//
// package.json holds: name, publisher, version, displayName, description,
// engines.vscode (API version), main (entry script), activationEvents,
// categories, keywords. The marketplace install also drops a
// `.vsixmanifest` next to package.json; presence indicates marketplace
// install, absence indicates a sideloaded `code --install-extension foo.vsix`.
type vscodeCollector struct {
	homeDirs func() []string
	readFile func(string) ([]byte, error)
	statFile func(string) (os.FileInfo, error)
	walkDir  func(string, fs.WalkDirFunc) error
	editors  []vscodeEditor
}

type vscodeEditor struct {
	editor      Editor
	extPath     string // relative to home dir
	profileName string // most VS Code forks use a single "default" profile on disk
}

// NewVSCodeCollector returns the default VS Code-family collector.
func NewVSCodeCollector() Collector {
	return &vscodeCollector{
		homeDirs: defaultHomeDirs,
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME-derived path
		statFile: os.Stat,
		walkDir:  filepath.WalkDir,
		editors:  vscodeExtensionPaths(),
	}
}

func (c *vscodeCollector) Name() string { return "vscode-family" }

func (c *vscodeCollector) Collect(ctx context.Context) ([]Extension, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Extension
	for _, home := range c.homeDirs() {
		for _, ed := range c.editors {
			root := filepath.Join(home, ed.extPath)
			out = append(out, c.collectEditor(ctx, ed, root)...)
			if len(out) >= MaxExtensions {
				SortExtensions(out)
				return out[:MaxExtensions], nil
			}
		}
	}
	SortExtensions(out)
	return out, nil
}

// collectEditor walks one editor's extensions directory and parses each
// package.json. Each top-level subdirectory is one installed extension
// (the directory name is `publisher.name-version`).
func (c *vscodeCollector) collectEditor(ctx context.Context, ed vscodeEditor, root string) []Extension {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []Extension
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out
		}
		if !e.IsDir() {
			continue
		}
		extPath := filepath.Join(root, e.Name())
		manifestPath := filepath.Join(extPath, "package.json")
		data, ferr := c.readFile(manifestPath)
		if ferr != nil {
			continue
		}
		ext, ok := parseVSCodeManifest(data)
		if !ok {
			slog.Debug("editorext: vscode manifest parse skipped",
				"path", manifestPath)
			continue
		}
		ext.Editor = ed.editor
		ext.Profile = ed.profileName
		ext.ExtensionPath = extPath
		ext.ManifestPath = manifestPath
		ext.ExtensionID = ext.Publisher + "." + ext.Name
		ext.InstallSource = vscodeClassifyInstall(c.statFile, extPath)
		ext.ActivatesOnStartup = HasStartupActivation(ext.ActivationEvents)
		out = append(out, ext)
		if len(out) >= MaxExtensions {
			return out
		}
	}
	return out
}

// vscodeManifest is the subset of package.json fields we extract.
type vscodeManifest struct {
	Name             string            `json:"name"`
	Publisher        string            `json:"publisher"`
	Version          string            `json:"version"`
	DisplayName      string            `json:"displayName"`
	Description      string            `json:"description"`
	Main             string            `json:"main"`
	Author           authorField       `json:"author"`
	Engines          map[string]string `json:"engines"`
	ActivationEvents []string          `json:"activationEvents"`
	Categories       []string          `json:"categories"`
	Keywords         []string          `json:"keywords"`
}

// authorField handles the two forms `author` can take in npm-style
// package.json: a bare string ("Alice <alice@example>") or an object
// ({"name":"Alice","email":"alice@example"}). We collapse to a string.
type authorField struct {
	value string
}

func (a *authorField) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		a.value = s
		return nil
	}
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		a.value = obj.Name
		return nil
	}
	a.value = ""
	return nil
}

// parseVSCodeManifest projects a package.json onto an Extension. Returns
// (Extension{}, false) when the manifest is malformed or missing the
// mandatory `name`/`publisher` pair.
func parseVSCodeManifest(raw []byte) (Extension, bool) {
	var m vscodeManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Extension{}, false
	}
	if m.Name == "" || m.Publisher == "" {
		return Extension{}, false
	}
	engine := ""
	if m.Engines != nil {
		engine = m.Engines["vscode"]
	}
	ext := Extension{
		Name:             m.Name,
		Publisher:        m.Publisher,
		Version:          m.Version,
		DisplayName:      m.DisplayName,
		Description:      m.Description,
		MainScript:       m.Main,
		Author:           m.Author.value,
		EngineVersion:    engine,
		ActivationEvents: append([]string(nil), m.ActivationEvents...),
		Categories:       append([]string(nil), m.Categories...),
		Keywords:         append([]string(nil), m.Keywords...),
	}
	sortStrings(ext.ActivationEvents)
	sortStrings(ext.Categories)
	sortStrings(ext.Keywords)
	return ext, true
}

// vscodeClassifyInstall infers install source from on-disk artefacts.
// Marketplace installs drop a `.vsixmanifest` in the extension dir
// (recorded by VS Code's gallery downloader). Sideloaded installs from
// a local .vsix do too actually — they extract the .vsix — so the
// distinguishing signal is whether the `.obsolete` marker is present
// OR whether the dir name matches the marketplace `publisher.name-version`
// canonical pattern (it always does for both, so this is best-effort
// "marketplace" for the common case; an offline-installer or a `code-server`
// SSH-remote install lands as "ssh-remote" when path contains "-server").
func vscodeClassifyInstall(statFn func(string) (os.FileInfo, error), extPath string) InstallSource {
	if strings.Contains(extPath, ".vscode-server") || strings.Contains(extPath, "code-server") {
		return InstallSSHRemote
	}
	if _, err := statFn(filepath.Join(extPath, ".vsixmanifest")); err == nil {
		return InstallMarketplace
	}
	// No vsixmanifest = either sideloaded raw-copy or dev-extension
	// (developer using `code --extensionDevelopmentPath=...`).
	return InstallSideloaded
}

// defaultHomeDirs returns the list of user home directories whose
// editor profiles we should scan. Same logic as the browser-extension
// walker (reused intentionally — same pattern).
func defaultHomeDirs() []string {
	return discoverHomes()
}

// vscodeExtensionPaths returns the per-editor extension directory
// (relative to $HOME). VS Code variants all use ~/.<flavour>/extensions.
func vscodeExtensionPaths() []vscodeEditor {
	return []vscodeEditor{
		{EditorVSCode, ".vscode/extensions", "default"},
		{EditorVSCodium, ".vscode-oss/extensions", "default"},
		{EditorCursor, ".cursor/extensions", "default"},
		{EditorWindsurf, ".windsurf/extensions", "default"},
		{EditorCodeServer, ".vscode-server/extensions", "default"},
	}
}
