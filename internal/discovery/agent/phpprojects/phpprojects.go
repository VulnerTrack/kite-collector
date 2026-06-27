// Package phpprojects discovers PHP projects on the local
// filesystem and classifies each one against the PHP-project
// fingerprint catalogue documented in iter 1-6 of this project's
// research notes. The catalogue covers 58 frameworks, CMSs,
// e-commerce platforms, forums, wikis, CRMs, ERPs, admin
// panels, static-site builders, and runtime layers.
//
// Detection uses Tier-A markers only (definitive file or CLI bin
// presence) for low false-positive rate. The walk visits a
// curated set of canonical install roots plus per-user
// public_html / Documents trees, and follows symlinks one level
// deep (Composer install layouts often symlink).
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource so the classification + risk-annotation logic is
// verifiable without touching the real filesystem.
//
// Read-only by intent. The collector reads marker files for
// classification + extracts small evidence snippets; it never
// writes, modifies, or executes any discovered project.
package phpprojects

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 4096
	MaxMarkerBytes = 256 << 10 // 256 KiB cap when hashing the marker file
	RecentlyWindow = 24 * time.Hour
)

// Framework is pinned to host_php_projects.framework.
type Framework string

const (
	FwUnknown      Framework = "unknown"
	FwLaravel      Framework = "laravel"
	FwLumen        Framework = "lumen"
	FwSymfony      Framework = "symfony"
	FwSlim         Framework = "slim"
	FwMezzio       Framework = "mezzio"
	FwHyperf       Framework = "hyperf"
	FwSpiral       Framework = "spiral"
	FwCodeIgniter3 Framework = "codeigniter3"
	FwCodeIgniter4 Framework = "codeigniter4"
	FwCakePHP      Framework = "cakephp"
	FwYii2         Framework = "yii2"
	FwPhalcon      Framework = "phalcon"
	FwLaminas      Framework = "laminas"
	FwWordPress    Framework = "wordpress"
	FwDrupal       Framework = "drupal"
	FwJoomla       Framework = "joomla"
	FwTypo3        Framework = "typo3"
	FwStatamic     Framework = "statamic"
	FwCraft        Framework = "craft"
	FwConcrete     Framework = "concrete"
	FwBolt         Framework = "bolt"
	FwProcessWire  Framework = "processwire"
	FwPico         Framework = "pico"
	FwGrav         Framework = "grav"
	FwOctoberCMS   Framework = "octobercms"
	FwWinterCMS    Framework = "wintercms"
	FwMagento      Framework = "magento"
	FwMagento2     Framework = "magento2"
	FwWooCommerce  Framework = "woocommerce"
	FwSylius       Framework = "sylius"
	FwShopware     Framework = "shopware"
	FwBagisto      Framework = "bagisto"
	FwPrestaShop   Framework = "prestashop"
	FwOpenCart     Framework = "opencart"
	FwPhpBB        Framework = "phpbb"
	FwMyBB         Framework = "mybb"
	FwFlarum       Framework = "flarum"
	FwMediaWiki    Framework = "mediawiki"
	FwDokuWiki     Framework = "dokuwiki"
	FwBookStack    Framework = "bookstack"
	FwSuiteCRM     Framework = "suitecrm"
	FwEspoCRM      Framework = "espocrm"
	FwVtiger       Framework = "vtiger"
	FwDolibarr     Framework = "dolibarr"
	FwGLPI         Framework = "glpi"
	FwMantis       Framework = "mantis"
	FwMoodle       Framework = "moodle"
	FwRoundcube    Framework = "roundcube"
	FwPostfixadmin Framework = "postfixadmin"
	FwISPConfig    Framework = "ispconfig"
	FwPhpMyAdmin   Framework = "phpmyadmin"
	FwAdminer      Framework = "adminer"
	FwFilament     Framework = "filament"
	FwNovaPanel    Framework = "novapanel"
	FwBackpack     Framework = "backpack"
	FwSculpin      Framework = "sculpin"
	FwJigsaw       Framework = "jigsaw"
	FwNextcloud    Framework = "nextcloud"
	FwOwnCloud     Framework = "owncloud"
	FwComposerOnly Framework = "composer-only"
	FwOther        Framework = "other"
)

// Family is pinned to host_php_projects.framework_family.
type Family string

const (
	FamUnknown        Family = "unknown"
	FamMicroFramework Family = "micro-framework"
	FamFullFramework  Family = "full-framework"
	FamCMS            Family = "cms"
	FamEcommerce      Family = "ecommerce"
	FamForum          Family = "forum"
	FamWiki           Family = "wiki"
	FamLMS            Family = "lms"
	FamCRM            Family = "crm"
	FamERP            Family = "erp"
	FamHelpdesk       Family = "helpdesk"
	FamMailAdmin      Family = "mail-admin"
	FamHostingPanel   Family = "hosting-panel"
	FamDBAdmin        Family = "db-admin"
	FamAdminPanel     Family = "admin-panel"
	FamStaticBuilder  Family = "static-builder"
	FamFileShare      Family = "file-share"
	FamComposerOnly   Family = "composer-only"
	FamOther          Family = "other"
)

// Confidence is pinned to host_php_projects.confidence.
type Confidence string

const (
	ConfUnknown Confidence = "unknown"
	ConfA       Confidence = "a" // definitive single-shot marker
	ConfB       Confidence = "b" // strong, single signal
	ConfC       Confidence = "c" // corroborating, ≥2 needed
	ConfD       Confidence = "d" // weak, filter unless paired
)

// Project mirrors the host_php_projects column shape.
type Project struct {
	ProjectRoot              string     `json:"project_root"`
	UserProfile              string     `json:"user_profile,omitempty"`
	Framework                Framework  `json:"framework"`
	FrameworkFamily          Family     `json:"framework_family"`
	DetectedVersion          string     `json:"detected_version,omitempty"`
	Evidence                 string     `json:"evidence,omitempty"`
	Confidence               Confidence `json:"confidence"`
	MarkerPath               string     `json:"marker_path,omitempty"`
	MarkerHash               string     `json:"marker_hash,omitempty"`
	ProjectSizeBytes         int64      `json:"project_size_bytes,omitempty"`
	FileCount                int        `json:"file_count,omitempty"`
	ComposerJSONPresent      bool       `json:"composer_json_present"`
	ComposerLockPresent      bool       `json:"composer_lock_present"`
	HasDotenv                bool       `json:"has_dotenv"`
	HasDotenvSecret          bool       `json:"has_dotenv_secret"`
	IsGitRepo                bool       `json:"is_git_repo"`
	HasVendorDir             bool       `json:"has_vendor_dir"`
	HasNodeModulesDir        bool       `json:"has_node_modules_dir"`
	HasInstallWizard         bool       `json:"has_install_wizard"`
	IsWorldWritableRoot      bool       `json:"is_world_writable_root"`
	IsWorldReadableConfig    bool       `json:"is_world_readable_config"`
	IsUnderWebRoot           bool       `json:"is_under_web_root"`
	IsRecent                 bool       `json:"is_recent"`
	IsDevArtifactLeakRisk    bool       `json:"is_dev_artifact_leak_risk"`
	IsCredentialExposureRisk bool       `json:"is_credential_exposure_risk"`
	IsOutdatedFrameworkRisk  bool       `json:"is_outdated_framework_risk"`
	IsInstallWizardLeftRisk  bool       `json:"is_install_wizard_left_risk"`
	IsWorldWritableRisk      bool       `json:"is_world_writable_risk"`
}

// Source is the per-OS enumerator.
type Source interface {
	Enumerate(ctx context.Context) ([]Project, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Project, error)
}

type collector struct {
	src Source
	now func() time.Time
}

// NewCollector returns the production collector backed by the
// per-OS Source registered at build time.
func NewCollector() Collector { return &collector{src: newSource(), now: time.Now} }

// NewCollectorWith lets tests inject a Source.
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }

func (c *collector) Name() string { return "phpprojects" }

func (c *collector) Collect(ctx context.Context) ([]Project, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("phpprojects enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortProjects(rows)
	return rows, nil
}

// Normalize back-fills FrameworkFamily from Framework, sets
// defaults, and ensures the confidence field is populated.
func Normalize(p *Project) {
	if p.Framework == "" {
		p.Framework = FwUnknown
	}
	if p.FrameworkFamily == "" || p.FrameworkFamily == FamUnknown {
		p.FrameworkFamily = FamilyFor(p.Framework)
	}
	if p.Confidence == "" {
		p.Confidence = ConfUnknown
	}
}

// Annotate sets the risk-rollup booleans + IsRecent.
//
//	is_dev_artifact_leak_risk     web-root project with .git or
//	                              vendor/ or node_modules/ present
//	is_credential_exposure_risk   .env exists with a secret-shaped
//	                              key OR world-readable config file
//	is_outdated_framework_risk    DetectedVersion < current LTS
//	                              for the framework (best-effort)
//	is_install_wizard_left_risk   /install/ /setup/ /installation/
//	                              dir found post-deploy
//	is_world_writable_risk        project root chmod 777
func Annotate(p *Project) {
	p.IsRecent = true
	devLeak := p.IsUnderWebRoot && (p.IsGitRepo || p.HasVendorDir || p.HasNodeModulesDir)
	p.IsDevArtifactLeakRisk = devLeak
	if (p.HasDotenv && p.HasDotenvSecret) || p.IsWorldReadableConfig {
		p.IsCredentialExposureRisk = true
	}
	if p.HasInstallWizard {
		p.IsInstallWizardLeftRisk = true
	}
	if p.IsWorldWritableRoot {
		p.IsWorldWritableRisk = true
	}
	if IsOutdated(p.Framework, p.DetectedVersion) {
		p.IsOutdatedFrameworkRisk = true
	}
}

// FamilyFor returns the family bucket for a framework. The map
// captures every value of the Framework enum; unknown values
// fall through to FamUnknown.
func FamilyFor(fw Framework) Family {
	switch fw {
	case FwLaravel, FwSymfony, FwCodeIgniter3, FwCodeIgniter4,
		FwCakePHP, FwYii2, FwPhalcon, FwLaminas, FwHyperf, FwSpiral:
		return FamFullFramework
	case FwLumen, FwSlim, FwMezzio:
		return FamMicroFramework
	case FwWordPress, FwDrupal, FwJoomla, FwTypo3, FwStatamic,
		FwCraft, FwConcrete, FwBolt, FwProcessWire, FwPico,
		FwGrav, FwOctoberCMS, FwWinterCMS:
		return FamCMS
	case FwMagento, FwMagento2, FwWooCommerce, FwSylius, FwShopware,
		FwBagisto, FwPrestaShop, FwOpenCart:
		return FamEcommerce
	case FwPhpBB, FwMyBB, FwFlarum:
		return FamForum
	case FwMediaWiki, FwDokuWiki, FwBookStack:
		return FamWiki
	case FwSuiteCRM, FwEspoCRM, FwVtiger:
		return FamCRM
	case FwDolibarr:
		return FamERP
	case FwGLPI, FwMantis:
		return FamHelpdesk
	case FwMoodle:
		return FamLMS
	case FwRoundcube, FwPostfixadmin:
		return FamMailAdmin
	case FwISPConfig:
		return FamHostingPanel
	case FwPhpMyAdmin, FwAdminer:
		return FamDBAdmin
	case FwFilament, FwNovaPanel, FwBackpack:
		return FamAdminPanel
	case FwSculpin, FwJigsaw:
		return FamStaticBuilder
	case FwNextcloud, FwOwnCloud:
		return FamFileShare
	case FwComposerOnly:
		return FamComposerOnly
	case FwOther, FwUnknown:
		return FamUnknown
	}
	return FamUnknown
}

// IsOutdated returns true when the detected_version of a framework
// is at least one major behind the framework's current LTS / stable
// (per October 2026 release calendars). The map is intentionally
// conservative — a missing entry means "we don't track LTS for this
// framework", which returns false rather than a false positive.
func IsOutdated(fw Framework, version string) bool {
	if version == "" {
		return false
	}
	majorLatest, ok := currentMajorLTS[fw]
	if !ok {
		return false
	}
	major := majorFromVersion(version)
	if major <= 0 {
		return false
	}
	return major < majorLatest
}

// currentMajorLTS pins the current stable major release for each
// framework we track outdated-risk for. Update when LTS shifts.
var currentMajorLTS = map[Framework]int{
	FwLaravel:      11,
	FwSymfony:      7,
	FwCodeIgniter4: 4,
	FwCakePHP:      5,
	FwYii2:         2,
	FwWordPress:    6,
	FwDrupal:       11,
	FwJoomla:       5,
	FwTypo3:        13,
	FwCraft:        5,
	FwGrav:         1,
	FwMagento2:     2,
	FwPrestaShop:   8,
	FwOpenCart:     4,
	FwPhpBB:        3,
	FwMediaWiki:    1, // version string starts with "1." for major
	FwMoodle:       4,
	FwRoundcube:    1,
	FwGLPI:         10,
	FwNextcloud:    30,
	FwOwnCloud:     10,
}

// majorFromVersion extracts the leading integer of a version
// string (e.g. "10.4.1" -> 10, "v6.5.0" -> 6, "30.x.x.x" -> 30).
// Returns 0 if the string doesn't look like a version.
func majorFromVersion(v string) int {
	t := strings.TrimSpace(v)
	t = strings.TrimPrefix(t, "v")
	t = strings.TrimPrefix(t, "V")
	if t == "" {
		return 0
	}
	end := 0
	for end < len(t) && t[end] >= '0' && t[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n := 0
	for i := 0; i < end; i++ {
		n = n*10 + int(t[i]-'0')
	}
	return n
}

// HashContents returns the SHA-256 hex of arbitrary bytes.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SortProjects returns deterministic ordering by project_root.
func SortProjects(ps []Project) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].ProjectRoot < ps[j].ProjectRoot })
}
