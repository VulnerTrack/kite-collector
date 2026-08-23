package network

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// pkgMgrComposer / pkgMgrNPM tag rows recovered from an exposed dependency
// manifest so downstream CVE matching knows the ecosystem.
const (
	pkgMgrComposer = "composer"
	pkgMgrNPM      = "npm"
)

// maxDisclosureBytes bounds each manifest read. A real composer.lock is a
// few hundred KB; the cap protects against a hostile or runaway endpoint.
const maxDisclosureBytes = 4 << 20 // 4 MiB

// maxDisclosureRows caps how many packages one host contributes, so a fat
// lockfile cannot flood the inventory.
const maxDisclosureRows = 500

// disclosurePaths are the dependency manifests probed for an exact version.
// The file fingerprint surface already flags these as an exposure *finding*;
// this layer parses the disclosed version into software so "Laravel" becomes
// "laravel/framework 11.9.2". Exact-version lockfiles are tried before their
// looser constraint manifests. Secrets files (.env) are deliberately absent:
// they carry no version and must never be fetched for inventory.
var disclosurePaths = []string{
	"/composer.lock",                  // exact PHP versions (primary Laravel signal)
	"/vendor/composer/installed.json", // exact PHP versions (installed set)
	"/composer.json",                  // PHP version constraints (fallback)
	"/package-lock.json",              // exact JS versions
	"/package.json",                   // JS version constraints (fallback)
}

// probeVersionDisclosure fetches each dependency manifest from a reachable
// web endpoint (via the caller's IP-pinned client, so it never leaves scan
// scope) and parses any that are exposed into versioned software rows. A
// manifest that 404s or returns non-JSON contributes nothing, so a
// well-configured host yields an empty result without false positives.
func probeVersionDisclosure(ctx context.Context, client *http.Client, scheme, host string, port int, timeout time.Duration) []model.InstalledSoftware {
	if client == nil {
		return nil
	}
	base := scheme + "://" + host + ":" + strconv.Itoa(port)

	var out []model.InstalledSoftware
	composerSeen := false
	npmSeen := false
	for _, path := range disclosurePaths {
		if ctx.Err() != nil || len(out) >= maxDisclosureRows {
			break
		}
		// Prefer the exact lockfile: once composer.lock/installed.json or
		// package-lock.json produced rows, skip the looser constraint
		// manifest for that ecosystem.
		if composerSeen && (path == "/composer.json") {
			continue
		}
		if npmSeen && path == "/package.json" {
			continue
		}

		body, ok := fetchManifest(ctx, client, base+path, timeout)
		if !ok {
			continue
		}
		var rows []model.InstalledSoftware
		switch path {
		case "/composer.lock":
			rows = parseComposerLock(body)
		case "/vendor/composer/installed.json":
			rows = parseInstalledJSON(body)
		case "/composer.json":
			rows = parseComposerJSON(body)
		case "/package-lock.json":
			rows = parsePackageLock(body)
		case "/package.json":
			rows = parsePackageJSON(body)
		}
		if len(rows) == 0 {
			continue
		}
		for i := range rows {
			rows[i].InstallPath = base + path
		}
		if strings.Contains(path, "composer") || strings.Contains(path, "installed.json") {
			composerSeen = true
		}
		if strings.Contains(path, "package") {
			npmSeen = true
		}
		out = append(out, rows...)
	}
	if len(out) > maxDisclosureRows {
		out = out[:maxDisclosureRows]
	}
	return out
}

// fetchManifest GETs one URL and returns its body when the response is a
// 200 with a JSON-ish content type or payload. Bounded by size and timeout.
func fetchManifest(ctx context.Context, client *http.Client, url string, timeout time.Duration) ([]byte, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "kite-collector/version-disclosure")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDisclosureBytes))
	if err != nil || len(body) == 0 {
		return nil, false
	}
	// Guard against a catch-all HTML 200 (SPA index / styled error page):
	// the first non-space byte of a manifest is '{' or '['.
	trimmed := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	return body, true
}

// composerPackage is the subset of a composer.lock / installed.json entry
// we read.
type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposerLock extracts exact versions from a composer.lock, covering
// both the runtime and dev package sets.
func parseComposerLock(body []byte) []model.InstalledSoftware {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		return nil
	}
	pkgs := append(append([]composerPackage{}, lock.Packages...), lock.PackagesDev...)
	return composerRows(pkgs)
}

// parseInstalledJSON handles vendor/composer/installed.json in both its
// modern ({"packages":[…]}) and legacy (bare array) shapes.
func parseInstalledJSON(body []byte) []model.InstalledSoftware {
	var modern struct {
		Packages []composerPackage `json:"packages"`
	}
	if err := json.Unmarshal(body, &modern); err == nil && len(modern.Packages) > 0 {
		return composerRows(modern.Packages)
	}
	var legacy []composerPackage
	if err := json.Unmarshal(body, &legacy); err == nil {
		return composerRows(legacy)
	}
	return nil
}

// parseComposerJSON reads the require / require-dev constraint maps as a
// fallback when no lockfile is exposed. Versions are constraints, not exact.
func parseComposerJSON(body []byte) []model.InstalledSoftware {
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil
	}
	merged := map[string]string{}
	for k, v := range manifest.Require {
		merged[k] = v
	}
	for k, v := range manifest.RequireDev {
		merged[k] = v
	}
	pkgs := make([]composerPackage, 0, len(merged))
	for name, constraint := range merged {
		// Skip the "php" and "ext-*" platform requirements: they are not
		// composer packages and pollute the inventory.
		if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			continue
		}
		pkgs = append(pkgs, composerPackage{Name: name, Version: constraint})
	}
	return composerRows(pkgs)
}

// composerRows converts composer packages to software rows, splitting the
// vendor/name form and normalising the version. Names are sorted so output
// is deterministic.
func composerRows(pkgs []composerPackage) []model.InstalledSoftware {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	out := make([]model.InstalledSoftware, 0, len(pkgs))
	for _, p := range pkgs {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		vendor := ""
		if idx := strings.Index(name, "/"); idx > 0 {
			vendor = name[:idx]
		}
		out = append(out, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         vendor,
			Version:        normalizeVersion(p.Version),
			PackageManager: pkgMgrComposer,
		})
	}
	return out
}

// parsePackageLock extracts exact JS versions from an npm package-lock.json,
// handling lockfile v2/v3 ("packages") and v1 ("dependencies").
func parsePackageLock(body []byte) []model.InstalledSoftware {
	var lock struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]struct{ Version string } `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		return nil
	}
	versions := map[string]string{}
	for path, entry := range lock.Packages {
		if path == "" || entry.Version == "" { // "" is the root project
			continue
		}
		name := path
		if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
			name = path[idx+len("node_modules/"):]
		}
		versions[name] = entry.Version
	}
	for name, entry := range lock.Dependencies {
		if entry.Version != "" {
			versions[name] = entry.Version
		}
	}
	return npmRows(versions)
}

// parsePackageJSON reads dependencies / devDependencies constraints as a
// fallback when no lockfile is exposed.
func parsePackageJSON(body []byte) []model.InstalledSoftware {
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil
	}
	merged := map[string]string{}
	for k, v := range manifest.Dependencies {
		merged[k] = v
	}
	for k, v := range manifest.DevDependencies {
		merged[k] = v
	}
	return npmRows(merged)
}

// npmRows converts an npm name→version map to software rows, splitting a
// scoped @scope/name into vendor and name. Deterministic by name.
func npmRows(versions map[string]string) []model.InstalledSoftware {
	names := make([]string, 0, len(versions))
	for name := range versions {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.InstalledSoftware, 0, len(names))
	for _, name := range names {
		vendor := ""
		if strings.HasPrefix(name, "@") {
			if idx := strings.Index(name, "/"); idx > 0 {
				vendor = name[:idx]
			}
		}
		out = append(out, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         vendor,
			Version:        normalizeVersion(versions[name]),
			PackageManager: pkgMgrNPM,
		})
	}
	return out
}

// normalizeVersion trims a composer "v" prefix and surrounding space while
// leaving constraint strings ("^11.0", ">=10.0") intact for the caller to
// recognise as non-exact.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}
