package phpprojects

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Marker is a single Tier-A fingerprint rule: presence of a
// file at `RelPath` (relative to the candidate project root)
// is sufficient to identify the framework. Some markers carry
// a body-content predicate that further disambiguates two
// frameworks sharing a file name (e.g. `version.php` is shared
// by Nextcloud and ownCloud — disambiguate by body contents).
type Marker struct {
	Framework  Framework
	RelPath    string
	Confidence Confidence
	// PathMustContain is a substring or regex (when wrapped in
	// `~...~`) tested against the file body. Empty = path presence
	// alone is sufficient.
	PathMustContain string
}

// MatchBody returns true when m has no body predicate, or when
// the predicate matches the file content.
func (m Marker) MatchBody(content []byte) bool {
	if m.PathMustContain == "" {
		return true
	}
	if strings.HasPrefix(m.PathMustContain, "~") && strings.HasSuffix(m.PathMustContain, "~") {
		pattern := m.PathMustContain[1 : len(m.PathMustContain)-1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.Match(content)
	}
	return strings.Contains(string(content), m.PathMustContain)
}

// CanonicalMarkers is the ordered Tier-A marker table. Ordering
// matters: the first marker that matches a candidate root wins.
// More-specific frameworks (Statamic, October, Lumen) appear
// before their parent (Laravel) so they win on overlap.
//
// PathMustContain disambiguates shared file names:
//   - version.php is shared by Nextcloud + ownCloud — body
//     contains "$vendor = 'nextcloud'" → Nextcloud
//   - artisan is shared by Laravel + Lumen — bootstrap/app.php
//     containing "Laravel\\Lumen\\Application" → Lumen
//   - bin/console is shared by any Symfony-derived app —
//     composer.json containing "shopware/core" → Shopware,
//     "sylius/sylius" → Sylius, else → Symfony
func CanonicalMarkers() []Marker {
	return []Marker{
		// File-share (most specific Laravel-overlay frameworks
		// first to win the artisan race).
		{Framework: FwNextcloud, RelPath: "version.php", PathMustContain: "$vendor = 'nextcloud'", Confidence: ConfA},
		{Framework: FwNextcloud, RelPath: "version.php", PathMustContain: "$OC_Channel", Confidence: ConfA},
		{Framework: FwOwnCloud, RelPath: "version.php", PathMustContain: "$OC_VersionString", Confidence: ConfA},
		{Framework: FwNextcloud, RelPath: "apps/spreed", Confidence: ConfA},

		// CMS Tier-A markers.
		{Framework: FwWordPress, RelPath: "wp-config.php", Confidence: ConfA},
		{Framework: FwWordPress, RelPath: "wp-includes/version.php", Confidence: ConfA},
		{Framework: FwDrupal, RelPath: "core/lib/Drupal.php", Confidence: ConfA},
		{Framework: FwDrupal, RelPath: "sites/default/settings.php", Confidence: ConfB},
		{Framework: FwJoomla, RelPath: "administrator/manifests/files/joomla.xml", Confidence: ConfA},
		{Framework: FwJoomla, RelPath: "configuration.php", PathMustContain: "class JConfig", Confidence: ConfA},
		{Framework: FwTypo3, RelPath: "typo3conf/LocalConfiguration.php", Confidence: ConfA},
		{Framework: FwConcrete, RelPath: "concrete/dispatcher.php", Confidence: ConfA},
		{Framework: FwBolt, RelPath: "config/bolt", Confidence: ConfA},
		{Framework: FwProcessWire, RelPath: "wire/core/ProcessWire.php", Confidence: ConfA},
		{Framework: FwPico, RelPath: "vendor/picocms/pico/lib/Pico.php", Confidence: ConfA},
		{Framework: FwGrav, RelPath: "system/defines.php", PathMustContain: "GRAV_VERSION", Confidence: ConfA},
		{Framework: FwGrav, RelPath: "bin/grav", Confidence: ConfA},

		// October / Winter CMS — sit on Laravel; need to win
		// the artisan race.
		{Framework: FwOctoberCMS, RelPath: "modules/system/classes/UpdateManager.php", Confidence: ConfA},
		{Framework: FwWinterCMS, RelPath: "modules/system/classes/winter/UpdateManager.php", Confidence: ConfA},

		// Statamic — sits on Laravel; ship distinctive content dir.
		{Framework: FwStatamic, RelPath: "vendor/statamic/cms/src/Statamic.php", Confidence: ConfA},

		// Craft CMS — sits on Yii2.
		{Framework: FwCraft, RelPath: "vendor/craftcms/cms/src/Craft.php", Confidence: ConfA},
		{Framework: FwCraft, RelPath: "craft", Confidence: ConfB},

		// E-commerce — most specific Laravel/Symfony-overlay first.
		{Framework: FwBagisto, RelPath: "packages/Webkul/Core/Providers/CoreServiceProvider.php", Confidence: ConfA},
		{Framework: FwShopware, RelPath: "vendor/shopware/core/Kernel.php", Confidence: ConfA},
		{Framework: FwSylius, RelPath: "vendor/sylius/sylius/src/Sylius/Bundle/CoreBundle/Application/Kernel.php", Confidence: ConfA},
		{Framework: FwMagento, RelPath: "app/Mage.php", Confidence: ConfA},
		{Framework: FwMagento2, RelPath: "bin/magento", Confidence: ConfA},
		{Framework: FwPrestaShop, RelPath: "config/defines.inc.php", PathMustContain: "_PS_VERSION_", Confidence: ConfA},
		{Framework: FwOpenCart, RelPath: "admin/config.php", PathMustContain: "HTTP_SERVER", Confidence: ConfA},

		// WooCommerce — sits on WordPress.
		{Framework: FwWooCommerce, RelPath: "wp-content/plugins/woocommerce/woocommerce.php", Confidence: ConfA},

		// Forums / wikis.
		{Framework: FwPhpBB, RelPath: "includes/constants.php", PathMustContain: "PHPBB_VERSION", Confidence: ConfA},
		{Framework: FwMyBB, RelPath: "inc/class_core.php", PathMustContain: "class MyBB", Confidence: ConfA},
		{Framework: FwFlarum, RelPath: "vendor/flarum/core/src/Application.php", Confidence: ConfA},
		{Framework: FwMediaWiki, RelPath: "includes/DefaultSettings.php", Confidence: ConfA},
		{Framework: FwMediaWiki, RelPath: "LocalSettings.php", Confidence: ConfA},
		{Framework: FwDokuWiki, RelPath: "doku.php", Confidence: ConfA},
		{Framework: FwBookStack, RelPath: "version", PathMustContain: "v", Confidence: ConfB},

		// CRM / ERP / helpdesk / LMS.
		{Framework: FwSuiteCRM, RelPath: "suitecrm_version.php", Confidence: ConfA},
		{Framework: FwSuiteCRM, RelPath: "sugar_version.php", Confidence: ConfB},
		{Framework: FwEspoCRM, RelPath: "application/Espo/Resources/defaults/config.php", Confidence: ConfA},
		{Framework: FwVtiger, RelPath: "vtigerversion.php", Confidence: ConfA},
		{Framework: FwDolibarr, RelPath: "htdocs/filefunc.inc.php", PathMustContain: "DOL_VERSION", Confidence: ConfA},
		{Framework: FwGLPI, RelPath: "inc/define.php", PathMustContain: "GLPI_VERSION", Confidence: ConfA},
		{Framework: FwMantis, RelPath: "core/constant_inc.php", PathMustContain: "MANTIS_VERSION", Confidence: ConfA},
		{Framework: FwMoodle, RelPath: "version.php", PathMustContain: "$release", Confidence: ConfA},

		// Mail-admin / hosting-panel / DB-admin.
		{Framework: FwRoundcube, RelPath: "program/include/iniset.php", PathMustContain: "RCUBE_VERSION", Confidence: ConfA},
		{Framework: FwPostfixadmin, RelPath: "model/Config.php", PathMustContain: "Postfixadmin\\Config", Confidence: ConfA},
		{Framework: FwISPConfig, RelPath: "interface/lib/config.inc.php", PathMustContain: "app_version", Confidence: ConfA},
		{Framework: FwPhpMyAdmin, RelPath: "libraries/classes/Config.php", Confidence: ConfA},
		{Framework: FwAdminer, RelPath: "adminer.php", Confidence: ConfA},

		// Static-site builders.
		{Framework: FwSculpin, RelPath: "app/config/sculpin_kernel.yml", Confidence: ConfA},
		{Framework: FwJigsaw, RelPath: "bootstrap.php", PathMustContain: "Jigsaw", Confidence: ConfA},

		// Frameworks (full-stack) — Lumen before Laravel.
		{Framework: FwLumen, RelPath: "bootstrap/app.php", PathMustContain: "Laravel\\Lumen\\Application", Confidence: ConfA},
		{Framework: FwLaravel, RelPath: "artisan", Confidence: ConfA},
		{Framework: FwSymfony, RelPath: "bin/console", Confidence: ConfA},
		{Framework: FwCodeIgniter4, RelPath: "spark", Confidence: ConfA},
		{Framework: FwCodeIgniter3, RelPath: "system/core/CodeIgniter.php", Confidence: ConfA},
		{Framework: FwCakePHP, RelPath: "bin/cake", Confidence: ConfA},
		{Framework: FwYii2, RelPath: "yii", Confidence: ConfA},
		{Framework: FwSlim, RelPath: "vendor/slim/slim/Slim/App.php", Confidence: ConfA},
		{Framework: FwMezzio, RelPath: "config/pipeline.php", Confidence: ConfB},
		{Framework: FwLaminas, RelPath: "config/application.config.php", Confidence: ConfB},
		{Framework: FwHyperf, RelPath: "bin/hyperf.php", Confidence: ConfA},
		{Framework: FwSpiral, RelPath: ".rr.yaml", Confidence: ConfB},

		// Admin panels — Laravel-package overlays.
		{Framework: FwFilament, RelPath: "app/Providers/Filament/AdminPanelProvider.php", Confidence: ConfA},
		{Framework: FwNovaPanel, RelPath: "nova-components", Confidence: ConfB},
		{Framework: FwBackpack, RelPath: "vendor/backpack/crud", Confidence: ConfA},
	}
}

// ClassifyDir runs the marker table against a directory and
// returns the first match (the table order encodes priority).
// `read` is the caller-provided file-read function (so this is
// OS-agnostic and tests can inject fakes).
//
// If no marker matches but a composer.json is present, the
// project is classified as composer-only.
func ClassifyDir(root string, exists func(string) bool, read func(string) ([]byte, error)) (Project, bool) {
	for _, m := range CanonicalMarkers() {
		marker := filepath.Join(root, m.RelPath)
		if !exists(marker) {
			continue
		}
		if m.PathMustContain != "" {
			data, err := read(marker)
			if err != nil {
				continue
			}
			if !m.MatchBody(data) {
				continue
			}
		}
		p := Project{
			ProjectRoot: root,
			Framework:   m.Framework,
			Confidence:  m.Confidence,
			MarkerPath:  m.RelPath,
			Evidence:    "marker file " + m.RelPath,
		}
		// Best-effort: hash the marker payload for drift
		// detection across re-scans.
		if data, err := read(marker); err == nil {
			if len(data) > MaxMarkerBytes {
				data = data[:MaxMarkerBytes]
			}
			p.MarkerHash = HashContents(data)
			// Best-effort version extraction.
			if v := ExtractVersion(m.Framework, string(data)); v != "" {
				p.DetectedVersion = v
			}
		}
		return p, true
	}
	// Fallback: composer.json without a recognised framework.
	composer := filepath.Join(root, "composer.json")
	if exists(composer) {
		p := Project{
			ProjectRoot: root,
			Framework:   FwComposerOnly,
			Confidence:  ConfB,
			MarkerPath:  "composer.json",
			Evidence:    "composer.json present, no recognised framework",
		}
		if data, err := read(composer); err == nil {
			if len(data) > MaxMarkerBytes {
				data = data[:MaxMarkerBytes]
			}
			p.MarkerHash = HashContents(data)
		}
		return p, true
	}
	return Project{}, false
}

// ExtractVersion pulls a version string from the marker file's
// contents using framework-specific shape rules. Best-effort —
// returns "" when the pattern doesn't match.
func ExtractVersion(fw Framework, body string) string {
	switch fw {
	case FwNextcloud, FwOwnCloud:
		// $OC_VersionString = '30.x.x';
		if m := versionRE(`\$OC_VersionString\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwWordPress:
		// $wp_version = '6.x.x';
		if m := versionRE(`\$wp_version\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwPhpBB:
		// define('PHPBB_VERSION', '3.3.x')
		if m := versionRE(`PHPBB_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwMantis:
		if m := versionRE(`MANTIS_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwGLPI:
		if m := versionRE(`GLPI_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwGrav:
		if m := versionRE(`GRAV_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwDolibarr:
		if m := versionRE(`DOL_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwMoodle:
		if m := versionRE(`\$release\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwSuiteCRM:
		// suitecrm_version.php has $suitecrm_version = '8.x';
		if m := versionRE(`\$suitecrm_version\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
		if m := versionRE(`\$sugar_version\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwVtiger:
		if m := versionRE(`\$vtiger_current_version\s*=\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwPrestaShop:
		if m := versionRE(`_PS_VERSION_['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwRoundcube:
		if m := versionRE(`RCUBE_VERSION['"]?\s*,\s*['"]([0-9][^'"]*)['"]`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case FwBookStack:
		// the version file is plain "v25.10.0"
		t := strings.TrimSpace(body)
		t = strings.TrimPrefix(t, "v")
		if t != "" && t[0] >= '0' && t[0] <= '9' {
			return t
		}
	case FwUnknown, FwLaravel, FwLumen, FwSymfony, FwSlim, FwMezzio,
		FwHyperf, FwSpiral, FwCodeIgniter3, FwCodeIgniter4, FwCakePHP,
		FwYii2, FwPhalcon, FwLaminas, FwDrupal, FwJoomla, FwTypo3,
		FwStatamic, FwCraft, FwConcrete, FwBolt, FwProcessWire,
		FwPico, FwOctoberCMS, FwWinterCMS, FwMagento, FwMagento2,
		FwWooCommerce, FwSylius, FwShopware, FwBagisto, FwOpenCart,
		FwMyBB, FwFlarum, FwMediaWiki, FwDokuWiki, FwEspoCRM,
		FwPostfixadmin, FwISPConfig, FwPhpMyAdmin, FwAdminer,
		FwFilament, FwNovaPanel, FwBackpack, FwSculpin, FwJigsaw,
		FwComposerOnly, FwOther:
		// Version extraction not yet implemented for this fw;
		// callers may parse composer.lock instead.
	}
	return ""
}

// versionRE is a tiny compile cache to avoid recompiling the
// same regex on every call. Single-threaded — the collector
// drives Source.Enumerate sequentially.
var versionREs = map[string]*regexp.Regexp{}

func versionRE(pattern string) *regexp.Regexp {
	if r, ok := versionREs[pattern]; ok {
		return r
	}
	r := regexp.MustCompile(pattern)
	versionREs[pattern] = r
	return r
}
