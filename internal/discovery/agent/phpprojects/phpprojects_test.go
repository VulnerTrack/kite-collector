package phpprojects

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{string(FwLaravel), "laravel"},
		{string(FwLumen), "lumen"},
		{string(FwSymfony), "symfony"},
		{string(FwWordPress), "wordpress"},
		{string(FwOctoberCMS), "octobercms"},
		{string(FwMagento2), "magento2"},
		{string(FwNextcloud), "nextcloud"},
		{string(FwOwnCloud), "owncloud"},
		{string(FwComposerOnly), "composer-only"},
		{string(FamCMS), "cms"},
		{string(FamFileShare), "file-share"},
		{string(FamMicroFramework), "micro-framework"},
		{string(ConfA), "a"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("enum drift: got %q want %q", c.got, c.want)
		}
	}
}

func TestFamilyForCoversAllFrameworks(t *testing.T) {
	// Every Framework constant must map to a non-Unknown family
	// (except FwUnknown / FwOther which legitimately map to FamUnknown).
	allFrameworks := []Framework{
		FwLaravel, FwLumen, FwSymfony, FwSlim, FwMezzio,
		FwHyperf, FwSpiral,
		FwCodeIgniter3, FwCodeIgniter4, FwCakePHP, FwYii2,
		FwPhalcon, FwLaminas,
		FwWordPress, FwDrupal, FwJoomla, FwTypo3, FwStatamic,
		FwCraft, FwConcrete, FwBolt, FwProcessWire, FwPico, FwGrav,
		FwOctoberCMS, FwWinterCMS,
		FwMagento, FwMagento2, FwWooCommerce, FwSylius, FwShopware,
		FwBagisto, FwPrestaShop, FwOpenCart,
		FwPhpBB, FwMyBB, FwFlarum,
		FwMediaWiki, FwDokuWiki, FwBookStack,
		FwSuiteCRM, FwEspoCRM, FwVtiger,
		FwDolibarr, FwGLPI, FwMantis, FwMoodle,
		FwRoundcube, FwPostfixadmin, FwISPConfig,
		FwPhpMyAdmin, FwAdminer,
		FwFilament, FwNovaPanel, FwBackpack,
		FwSculpin, FwJigsaw,
		FwNextcloud, FwOwnCloud,
		FwComposerOnly,
	}
	for _, fw := range allFrameworks {
		fam := FamilyFor(fw)
		if fam == FamUnknown {
			t.Fatalf("framework %q has no family", fw)
		}
	}
	// Sanity: unknown and other map to FamUnknown.
	if FamilyFor(FwUnknown) != FamUnknown {
		t.Fatal("Unknown framework must map to FamUnknown")
	}
	if FamilyFor(FwOther) != FamUnknown {
		t.Fatal("Other framework must map to FamUnknown")
	}
}

func TestMajorFromVersion(t *testing.T) {
	cases := map[string]int{
		"10.4.1":   10,
		"v6.5.0":   6,
		"V11.2":    11,
		"30.0.0.4": 30,
		"3.x.x":    3,
		"":         0,
		"abc":      0,
		" 5":       5,
		"4-rc1":    4,
	}
	for in, want := range cases {
		if got := majorFromVersion(in); got != want {
			t.Fatalf("majorFromVersion(%q)=%d want %d", in, got, want)
		}
	}
}

func TestIsOutdated(t *testing.T) {
	if !IsOutdated(FwLaravel, "9.5.0") {
		t.Fatal("Laravel 9 must be flagged as outdated (current=11)")
	}
	if IsOutdated(FwLaravel, "11.0.0") {
		t.Fatal("Laravel 11 must NOT be flagged")
	}
	if IsOutdated(FwLaravel, "12.0.0") {
		t.Fatal("Laravel 12 (future major) must NOT be flagged")
	}
	if IsOutdated(FwNextcloud, "27.1.5") != true {
		t.Fatal("Nextcloud 27 must be flagged (current=30)")
	}
	if IsOutdated(FwNextcloud, "30.0.0.4") {
		t.Fatal("Nextcloud 30 must NOT be flagged")
	}
	// Frameworks without an LTS entry must never flag.
	if IsOutdated(FwSlim, "3.0.0") {
		t.Fatal("Slim has no LTS entry — must not flag")
	}
	// Empty version must not flag.
	if IsOutdated(FwLaravel, "") {
		t.Fatal("empty version must not flag")
	}
}

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		fw   Framework
		body string
		want string
	}{
		{FwNextcloud, `<?php $OC_VersionString = '30.0.4'; $OC_Channel = 'stable';`, "30.0.4"},
		{FwWordPress, `<?php $wp_version = '6.7.1';`, "6.7.1"},
		{FwPhpBB, `<?php define('PHPBB_VERSION', '3.3.11');`, "3.3.11"},
		{FwMantis, `<?php define('MANTIS_VERSION', '2.27.0');`, "2.27.0"},
		{FwGLPI, `<?php define('GLPI_VERSION', '10.0.18');`, "10.0.18"},
		{FwGrav, `<?php define('GRAV_VERSION', '1.7.50');`, "1.7.50"},
		{FwDolibarr, `<?php define('DOL_VERSION', '20.0.0');`, "20.0.0"},
		{FwMoodle, `<?php $release = '4.5.0+ (Build: 20251001)';`, "4.5.0+ (Build: 20251001)"},
		{FwSuiteCRM, `<?php $suitecrm_version = '8.7.0';`, "8.7.0"},
		{FwVtiger, `<?php $vtiger_current_version = '8.2.0';`, "8.2.0"},
		{FwPrestaShop, `<?php define('_PS_VERSION_', '8.2.0');`, "8.2.0"},
		{FwRoundcube, `<?php define('RCUBE_VERSION', '1.6.7');`, "1.6.7"},
		{FwBookStack, "v25.10.0\n", "25.10.0"},
	}
	for _, c := range cases {
		got := ExtractVersion(c.fw, c.body)
		if got != c.want {
			t.Fatalf("ExtractVersion(%q, body) = %q, want %q", c.fw, got, c.want)
		}
	}
}

func TestNormalizeFillsDefaults(t *testing.T) {
	p := Project{ProjectRoot: "/var/www/x", Framework: FwLaravel}
	Normalize(&p)
	if p.FrameworkFamily != FamFullFramework {
		t.Fatalf("family=%q", p.FrameworkFamily)
	}
	if p.Confidence != ConfUnknown {
		t.Fatalf("conf=%q", p.Confidence)
	}
}

func TestAnnotateDevArtifactLeakRisk(t *testing.T) {
	p := Project{
		ProjectRoot:    "/var/www/html",
		Framework:      FwLaravel,
		IsUnderWebRoot: true,
		IsGitRepo:      true,
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsDevArtifactLeakRisk {
		t.Fatal(".git in /var/www/html must flag dev artifact leak risk")
	}
}

func TestAnnotateNoDevLeakWhenNotUnderWebRoot(t *testing.T) {
	p := Project{
		ProjectRoot:    "/home/dev/projects/x",
		Framework:      FwLaravel,
		IsUnderWebRoot: false,
		IsGitRepo:      true,
	}
	Normalize(&p)
	Annotate(&p)
	if p.IsDevArtifactLeakRisk {
		t.Fatal(".git in /home/dev/projects must NOT flag (not under web root)")
	}
}

func TestAnnotateCredentialExposureViaDotenv(t *testing.T) {
	p := Project{
		Framework:       FwLaravel,
		HasDotenv:       true,
		HasDotenvSecret: true,
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsCredentialExposureRisk {
		t.Fatal(".env with secret-shaped key must flag credential exposure risk")
	}
}

func TestAnnotateCredentialExposureViaWorldReadableConfig(t *testing.T) {
	p := Project{
		Framework:             FwWordPress,
		IsWorldReadableConfig: true,
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsCredentialExposureRisk {
		t.Fatal("world-readable config must flag credential exposure risk")
	}
}

func TestAnnotateInstallWizardLeftRisk(t *testing.T) {
	p := Project{
		Framework:        FwPhpBB,
		HasInstallWizard: true,
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsInstallWizardLeftRisk {
		t.Fatal("/install/ dir present must flag install wizard left risk")
	}
}

func TestAnnotateOutdatedFrameworkRisk(t *testing.T) {
	p := Project{
		Framework:       FwLaravel,
		DetectedVersion: "8.83.27",
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsOutdatedFrameworkRisk {
		t.Fatalf("Laravel 8 must flag outdated risk: %+v", p)
	}
}

func TestAnnotateWorldWritableRisk(t *testing.T) {
	p := Project{
		Framework:           FwWordPress,
		IsWorldWritableRoot: true,
	}
	Normalize(&p)
	Annotate(&p)
	if !p.IsWorldWritableRisk {
		t.Fatal("world-writable root must flag risk")
	}
}

func TestClassifyDirLaravel(t *testing.T) {
	files := map[string][]byte{
		"/projects/myapp/artisan":           []byte("#!/usr/bin/env php\n<?php\nrequire __DIR__.'/bootstrap/app.php';\n"),
		"/projects/myapp/bootstrap/app.php": []byte("<?php $app = require_once __DIR__.'/../bootstrap/app.php';\nreturn $app;"),
	}
	p, ok := ClassifyDir("/projects/myapp", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify as Laravel")
	}
	if p.Framework != FwLaravel {
		t.Fatalf("fw=%q", p.Framework)
	}
	if p.Confidence != ConfA {
		t.Fatalf("conf=%q", p.Confidence)
	}
}

func TestClassifyDirLumenBeatsLaravel(t *testing.T) {
	// Lumen ships an artisan bin too, but its bootstrap/app.php
	// references Laravel\Lumen\Application — the disambiguator.
	files := map[string][]byte{
		"/projects/api/artisan":           []byte("#!/usr/bin/env php\n<?php"),
		"/projects/api/bootstrap/app.php": []byte("<?php\n$app = new Laravel\\Lumen\\Application(__DIR__);\nreturn $app;"),
	}
	p, ok := ClassifyDir("/projects/api", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify")
	}
	if p.Framework != FwLumen {
		t.Fatalf("fw=%q — Lumen must win the artisan race via bootstrap/app.php body", p.Framework)
	}
}

func TestClassifyDirNextcloudBeatsOwnCloud(t *testing.T) {
	files := map[string][]byte{
		"/srv/nc/version.php": []byte("<?php\n$OC_Version = [30, 0, 0, 4];\n$OC_VersionString = '30.0.4';\n$OC_Channel = 'stable';\n$OC_Build = 'abc';\n$vendor = 'nextcloud';\n"),
	}
	p, ok := ClassifyDir("/srv/nc", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify")
	}
	if p.Framework != FwNextcloud {
		t.Fatalf("fw=%q — vendor='nextcloud' must beat ownCloud", p.Framework)
	}
	if p.DetectedVersion != "30.0.4" {
		t.Fatalf("version=%q", p.DetectedVersion)
	}
}

func TestClassifyDirOwnCloudFallback(t *testing.T) {
	// version.php with $OC_VersionString but no $vendor='nextcloud' AND no $OC_Channel
	// → second Nextcloud rule won't match; third (ownCloud) rule matches.
	files := map[string][]byte{
		"/srv/oc/version.php": []byte("<?php\n$OC_VersionString = '10.15.0';\n"),
	}
	p, ok := ClassifyDir("/srv/oc", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify")
	}
	if p.Framework != FwOwnCloud {
		t.Fatalf("fw=%q want owncloud", p.Framework)
	}
}

func TestClassifyDirComposerOnlyFallback(t *testing.T) {
	files := map[string][]byte{
		"/projects/standalone/composer.json": []byte(`{"name":"vendor/pkg","require":{"php":"^8.2"}}`),
	}
	p, ok := ClassifyDir("/projects/standalone", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("composer.json alone must classify as composer-only")
	}
	if p.Framework != FwComposerOnly {
		t.Fatalf("fw=%q", p.Framework)
	}
}

func TestClassifyDirReturnsFalseWhenNoMarker(t *testing.T) {
	files := map[string][]byte{"/projects/blank/README.md": []byte("nothing")}
	_, ok := ClassifyDir("/projects/blank", existsFromMap(files), readFromMap(files))
	if ok {
		t.Fatal("blank dir must NOT classify")
	}
}

func TestClassifyDirWordPress(t *testing.T) {
	files := map[string][]byte{
		"/var/www/html/wp-config.php":           []byte("<?php define('DB_NAME','x');"),
		"/var/www/html/wp-includes/version.php": []byte("<?php $wp_version = '6.7.1';"),
	}
	p, ok := ClassifyDir("/var/www/html", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify")
	}
	if p.Framework != FwWordPress {
		t.Fatalf("fw=%q", p.Framework)
	}
}

func TestClassifyDirPhpMyAdmin(t *testing.T) {
	files := map[string][]byte{
		"/usr/share/phpmyadmin/libraries/classes/Config.php": []byte("<?php\nclass Config { const VERSION_CHECK_DEFAULT = ...; }"),
	}
	p, ok := ClassifyDir("/usr/share/phpmyadmin", existsFromMap(files), readFromMap(files))
	if !ok {
		t.Fatal("must classify")
	}
	if p.Framework != FwPhpMyAdmin {
		t.Fatalf("fw=%q", p.Framework)
	}
}

func TestSortProjectsDeterministic(t *testing.T) {
	ps := []Project{
		{ProjectRoot: "/var/www/c"},
		{ProjectRoot: "/var/www/a"},
		{ProjectRoot: "/var/www/b"},
	}
	SortProjects(ps)
	if ps[0].ProjectRoot != "/var/www/a" {
		t.Fatalf("sort drift: %+v", ps)
	}
}

type fakeSource struct {
	err  error
	rows []Project
}

func (f fakeSource) Enumerate(_ context.Context) ([]Project, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	src := fakeSource{rows: []Project{
		{ProjectRoot: "/var/www/x", Framework: FwLaravel, DetectedVersion: "8.0.0", IsUnderWebRoot: true, IsGitRepo: true},
		{ProjectRoot: "/srv/oc", Framework: FwOwnCloud, DetectedVersion: "10.15.0"},
	}}
	got, err := NewCollectorWith(src).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[1].IsDevArtifactLeakRisk {
		t.Fatalf("dev leak risk missing on Laravel under web root with .git: %+v", got[1])
	}
	if !got[1].IsOutdatedFrameworkRisk {
		t.Fatalf("outdated risk missing on Laravel 8: %+v", got[1])
	}
	if got[0].FrameworkFamily != FamFileShare {
		t.Fatalf("ownCloud family=%q", got[0].FrameworkFamily)
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("php fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "phpprojects" {
		t.Fatal("name drift")
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("hello"))
	b := HashContents([]byte("hello"))
	if a != b {
		t.Fatal("hash must be deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

// ---- helpers ----

// existsFromMap returns an exists() func backed by a map keyed
// on full paths.
func existsFromMap(m map[string][]byte) func(string) bool {
	return func(p string) bool {
		_, ok := m[p]
		return ok
	}
}

// readFromMap returns a read() func backed by a map keyed on
// full paths.
func readFromMap(m map[string][]byte) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return v, nil
		}
		return nil, os.ErrNotExist
	}
}
