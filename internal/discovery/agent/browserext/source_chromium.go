package browserext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// chromiumCollector walks every known Chromium-family browser profile
// and parses each extension's manifest.json. The on-disk layout is
// identical across Chrome / Edge / Brave / Opera / etc. — the only
// difference is the user-data root directory.
//
// Layout (Chromium):
//
//	<user-data-root>/Default/Extensions/<ext-id>/<version>/manifest.json
//	<user-data-root>/Profile N/Extensions/<ext-id>/<version>/manifest.json
//
// manifest.json holds: name, version, description, manifest_version,
// permissions (array), host_permissions (array), update_url. The CRX
// install source isn't directly in manifest.json — we infer it from
// update_url (official store URL → store, anything else → enterprise/
// sideloaded).
type chromiumCollector struct {
	homeDirs func() []string // for tests
	readFile func(string) ([]byte, error)
	walkDir  func(string, fs.WalkDirFunc) error
	browsers []chromiumBrowser
}

type chromiumBrowser struct {
	browser  Browser
	userData string // relative to home dir; built by chromiumUserDataPaths()
}

// NewChromiumCollector returns the default Chromium-family collector
// for the current OS.
func NewChromiumCollector() Collector {
	return &chromiumCollector{
		homeDirs: defaultHomeDirs,
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- profile paths derived from $HOME
		walkDir:  filepath.WalkDir,
		browsers: chromiumUserDataPaths(),
	}
}

func (c *chromiumCollector) Name() string { return "chromium-family" }

func (c *chromiumCollector) Collect(ctx context.Context) ([]Extension, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Extension
	for _, home := range c.homeDirs() {
		for _, b := range c.browsers {
			root := filepath.Join(home, b.userData)
			profiles := findChromiumProfiles(root, c.walkDir)
			for _, prof := range profiles {
				out = append(out, c.collectProfile(ctx, b.browser, root, prof)...)
				if len(out) >= MaxExtensions {
					SortExtensions(out)
					return out[:MaxExtensions], nil
				}
			}
		}
	}
	SortExtensions(out)
	return out, nil
}

// collectProfile enumerates one Chromium profile's Extensions/ tree.
func (c *chromiumCollector) collectProfile(ctx context.Context, br Browser, root, profile string) []Extension {
	extDir := filepath.Join(root, profile, "Extensions")
	var out []Extension
	err := c.walkDir(extDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries
		}
		if !d.IsDir() {
			return nil
		}
		// We're looking for paths of the shape:
		//   <extDir>/<ext-id>/<version>/
		// containing a manifest.json. Detect by depth.
		rel, rerr := filepath.Rel(extDir, path)
		if rerr != nil || rel == "." {
			return nil //nolint:nilerr // rel-path failure is non-fatal — skip this entry
		}
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) != 2 {
			return nil
		}
		manifestPath := filepath.Join(path, "manifest.json")
		data, ferr := c.readFile(manifestPath)
		if ferr != nil {
			return nil //nolint:nilerr // missing manifest.json = not an installed extension dir
		}
		ext, ok := parseChromiumManifest(data)
		if !ok {
			slog.Debug("browserext: manifest parse skipped", "path", manifestPath)
			return nil
		}
		ext.Browser = br
		ext.Profile = profile
		ext.ProfilePath = filepath.Join(root, profile)
		ext.ExtensionID = parts[0]
		ext.ManifestPath = manifestPath
		ext.InstallSource = classifyInstallSource(ext.UpdateURL)
		ext.Enabled = true // Chromium disables by Preferences edits, not by removing the dir
		out = append(out, ext)
		if len(out) >= MaxExtensions {
			return filepath.SkipAll
		}
		return ctx.Err()
	})
	if err != nil && err != filepath.SkipAll && !os.IsNotExist(err) {
		slog.Debug("browserext: walk error",
			"browser", string(br), "profile", profile, "error", err)
	}
	return out
}

// findChromiumProfiles returns the basename of every directory in the
// user-data root that looks like a Chromium profile ("Default", "Profile 1",
// "Profile 2", ...). Profile directories all contain a "Preferences" file.
func findChromiumProfiles(root string, walkDir func(string, fs.WalkDirFunc) error) []string {
	var out []string
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == "Default", strings.HasPrefix(name, "Profile "):
			// Sanity-check for Preferences file (cheap) before adding.
			if _, err := os.Stat(filepath.Join(root, name, "Preferences")); err == nil {
				out = append(out, name)
			}
		}
	}
	_ = walkDir // reserved for future deep-walk patterns
	return out
}

// chromiumManifest is the subset of fields we extract. The schema is
// large; we project to the audit-relevant bits.
type chromiumManifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	UpdateURL       string            `json:"update_url"`
	Permissions     []json.RawMessage `json:"permissions"`
	HostPermissions []string          `json:"host_permissions"`
	ManifestVersion int               `json:"manifest_version"`
}

// parseChromiumManifest extracts the audit-relevant fields. Returns
// (Extension, true) on success; (Extension{}, false) when the input is
// unparseable. `permissions` is a heterogeneous array (strings OR
// objects in MV3); we coerce to a flat string slice.
func parseChromiumManifest(raw []byte) (Extension, bool) {
	var m chromiumManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Extension{}, false
	}
	if m.Name == "" && m.Version == "" {
		return Extension{}, false
	}
	perms := make([]string, 0, len(m.Permissions))
	for _, raw := range m.Permissions {
		// Try string first.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			perms = append(perms, s)
			continue
		}
		// Skip objects (e.g. {"declarativeNetRequest": {...}}) — they're
		// API capability requests, not actionable for our audit which
		// only cares about plain permission names + host patterns.
	}
	hostPerms := append([]string(nil), m.HostPermissions...)
	sortStrings(perms)
	sortStrings(hostPerms)
	return Extension{
		ManifestVersion: m.ManifestVersion,
		Name:            m.Name,
		Version:         m.Version,
		Description:     m.Description,
		UpdateURL:       m.UpdateURL,
		Permissions:     perms,
		HostPermissions: hostPerms,
	}, true
}

// classifyInstallSource maps update_url to an InstallSource heuristic.
//
//   - empty → likely sideloaded or store (Chromium defaults to store
//     when omitted but only for off-store-tracked installs; treat as
//     'store' for the conservative case).
//   - clients2.google.com → Chrome Web Store
//   - edge.microsoft.com  → Edge Add-ons Store
//   - addons.opera.com    → Opera Add-ons
//   - chrome.google.com   → official store mirror
//   - anything else       → enterprise-policy or sideloaded
func classifyInstallSource(updateURL string) InstallSource {
	if updateURL == "" {
		return InstallStore
	}
	lower := strings.ToLower(updateURL)
	switch {
	case strings.Contains(lower, "clients2.google.com"),
		strings.Contains(lower, "chrome.google.com"),
		strings.Contains(lower, "edge.microsoft.com"),
		strings.Contains(lower, "addons.opera.com"):
		return InstallStore
	}
	return InstallEnterprisePolicy
}

// defaultHomeDirs returns the list of user home directories whose
// browser profiles we should scan. The kite-collector agent typically
// runs as a service so we don't know which user is "the user" — we walk
// every /home/* (Linux), every /Users/* (macOS), every C:\Users\* on
// Windows. Excludes system accounts.
func defaultHomeDirs() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return listSubdirs("/home")
	case "darwin":
		return listSubdirs("/Users")
	case "windows":
		users := os.Getenv("SystemDrive") + `\Users`
		if users == `\Users` {
			users = `C:\Users`
		}
		return listSubdirs(users)
	}
	return nil
}

// listSubdirs returns absolute paths of every immediate sub-directory of
// root whose name doesn't start with a dot (Linux dotfile dirs) and
// isn't a known system-account name.
func listSubdirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if isSystemUser(name) {
			continue
		}
		out = append(out, filepath.Join(root, name))
	}
	return out
}

func isSystemUser(name string) bool {
	switch strings.ToLower(name) {
	case "shared", "guest", "public", "default", "all users",
		"defaultappuser", "defaultaccount", "wdagutilityaccount":
		return true
	}
	return false
}

// chromiumUserDataPaths returns the per-OS user-data path (relative to
// $HOME) for every supported Chromium-family browser.
func chromiumUserDataPaths() []chromiumBrowser {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []chromiumBrowser{
			{BrowserChrome, ".config/google-chrome"},
			{BrowserChromium, ".config/chromium"},
			{BrowserEdge, ".config/microsoft-edge"},
			{BrowserBrave, ".config/BraveSoftware/Brave-Browser"},
			{BrowserOpera, ".config/opera"},
			{BrowserVivaldi, ".config/vivaldi"},
		}
	case "darwin":
		return []chromiumBrowser{
			{BrowserChrome, "Library/Application Support/Google/Chrome"},
			{BrowserChromium, "Library/Application Support/Chromium"},
			{BrowserEdge, "Library/Application Support/Microsoft Edge"},
			{BrowserBrave, "Library/Application Support/BraveSoftware/Brave-Browser"},
			{BrowserOpera, "Library/Application Support/com.operasoftware.Opera"},
			{BrowserVivaldi, "Library/Application Support/Vivaldi"},
			{BrowserArc, "Library/Application Support/Arc/User Data"},
		}
	case "windows":
		return []chromiumBrowser{
			{BrowserChrome, `AppData\Local\Google\Chrome\User Data`},
			{BrowserChromium, `AppData\Local\Chromium\User Data`},
			{BrowserEdge, `AppData\Local\Microsoft\Edge\User Data`},
			{BrowserBrave, `AppData\Local\BraveSoftware\Brave-Browser\User Data`},
			{BrowserOpera, `AppData\Roaming\Opera Software\Opera Stable`},
			{BrowserVivaldi, `AppData\Local\Vivaldi\User Data`},
		}
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
