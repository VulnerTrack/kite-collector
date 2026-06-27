package browserext

import "context"

// Stubs for sources not yet wired. Each returns empty so the multi-
// source chain runs unconditionally. Replace as each lands.

// NewFirefoxCollector returns a stub Firefox collector.
//
// TODO(cdms-iter): walk Firefox profile directories and parse
// `extensions.json` (the consolidated installed-extension index) +
// per-extension `manifest.json` inside `*.xpi` archives. Profile paths:
//
//	Linux:   ~/.mozilla/firefox/profiles.ini → walk each profile
//	macOS:   ~/Library/Application Support/Firefox/profiles.ini
//	Windows: %APPDATA%\Mozilla\Firefox\profiles.ini
//
// Firefox uses GUIDs for extension IDs, manifest_version=2 or 3 same as
// Chromium. Install source comes from `installType` in extensions.json
// ("normal", "sideloaded", "enterprise", "system").
func NewFirefoxCollector() Collector { return sourceStub{name: "firefox-stub"} }

// NewSafariCollector returns a stub Safari collector.
//
// TODO(cdms-iter): macOS-only. Safari extensions ship as App Extensions
// bundled inside .app packages (and signed via Apple ID). Enumerate via
//
//	pluginkit -m -A -v
//
// (lists all NSExtension instances; filter to `com.apple.Safari.web-extension`
// and `com.apple.Safari.extension`). Per-extension metadata lives in
// `~/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions/*.appex/Contents/Info.plist`.
func NewSafariCollector() Collector { return sourceStub{name: "safari-stub"} }

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Extension, error) {
	return []Extension{}, nil
}
