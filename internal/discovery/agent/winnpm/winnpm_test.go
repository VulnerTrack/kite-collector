package winnpm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`{"name":"x"}`))
	b := HashContents([]byte(`{"name":"x"}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsScopedName(t *testing.T) {
	for _, n := range []string{"@scope/name", "@org/pkg"} {
		if !IsScopedName(n) {
			t.Fatalf("%q must flag scoped", n)
		}
	}
	for _, n := range []string{"plain", "", "name-with-@inside"} {
		if IsScopedName(n) {
			t.Fatalf("%q must NOT flag scoped", n)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"a"}); got != `["a"]` {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateCleanScopedPackage(t *testing.T) {
	p := Package{
		Name:          "@org/pkg",
		License:       "MIT",
		Homepage:      "https://example.com",
		RepositoryURL: "https://example.com/repo",
	}
	AnnotateSecurity(&p)
	if !p.IsScopedPackage {
		t.Fatal("@org/pkg must flag scoped")
	}
	if p.HasNoLicense || p.HasNoHomepage || p.HasNoRepository {
		t.Fatalf("present fields must clear missing flags: %+v", p)
	}
	if p.HasInstallScripts || p.HasBinEntries {
		t.Fatal("no install scripts / bins → flags cleared")
	}
}

func TestAnnotateInstallScriptPackage(t *testing.T) {
	p := Package{
		Name:               "danger-pkg",
		InstallScriptNames: []string{"postinstall"},
	}
	AnnotateSecurity(&p)
	if !p.HasInstallScripts {
		t.Fatal("postinstall must flag install scripts")
	}
}

func TestAnnotateBinEntries(t *testing.T) {
	p := Package{Name: "x", BinEntries: []string{"cli"}}
	AnnotateSecurity(&p)
	if !p.HasBinEntries {
		t.Fatal("bin entries must flag")
	}
}

func TestAnnotateMissingMetadata(t *testing.T) {
	p := Package{Name: "barebones"}
	AnnotateSecurity(&p)
	if !p.HasNoLicense || !p.HasNoHomepage || !p.HasNoRepository {
		t.Fatalf("empty metadata must flag missing: %+v", p)
	}
}

// -- ParseManifest end-to-end ---------------------------------------

func TestParseManifestTypicalScopedPackage(t *testing.T) {
	body := []byte(`{
        "name": "@vendor/cli",
        "version": "2.4.1",
        "description": "Vendor CLI",
        "license": "Apache-2.0",
        "author": "Vendor Inc.",
        "homepage": "https://vendor.example.com",
        "repository": { "type": "git", "url": "https://github.com/vendor/cli" },
        "main": "./dist/index.js",
        "engines": { "node": ">=18" },
        "dependencies": { "axios": "^1.6.0", "chalk": "^5.3.0" },
        "bin": { "vendor": "./dist/cli.js" },
        "scripts": { "postinstall": "node ./scripts/install.js", "build": "tsc" }
    }`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "@vendor/cli" || !got.IsScopedPackage {
		t.Fatalf("scoped name: %+v", got)
	}
	if got.Version != "2.4.1" {
		t.Fatalf("version=%q", got.Version)
	}
	if got.License != "Apache-2.0" {
		t.Fatalf("license=%q", got.License)
	}
	if got.Author != "Vendor Inc." {
		t.Fatalf("author=%q", got.Author)
	}
	if got.RepositoryURL != "https://github.com/vendor/cli" {
		t.Fatalf("repo=%q", got.RepositoryURL)
	}
	if got.EngineNode != ">=18" {
		t.Fatalf("engine=%q", got.EngineNode)
	}
	if len(got.Dependencies) != 2 || got.DependencyCount != 2 {
		t.Fatalf("deps: %+v", got.Dependencies)
	}
	if len(got.BinEntries) != 1 || got.BinEntries[0] != "vendor" {
		t.Fatalf("bin: %+v", got.BinEntries)
	}
	if len(got.InstallScriptNames) != 1 || got.InstallScriptNames[0] != "postinstall" {
		t.Fatalf("scripts: %+v", got.InstallScriptNames)
	}
	if !got.HasInstallScripts || !got.HasBinEntries {
		t.Fatal("rollups must flip")
	}
}

func TestParseManifestLicenseObjectForm(t *testing.T) {
	body := []byte(`{"name":"x","version":"1","license":{"type":"BSD-3-Clause"}}`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.License != "BSD-3-Clause" {
		t.Fatalf("license=%q", got.License)
	}
}

func TestParseManifestRepositoryStringForm(t *testing.T) {
	body := []byte(`{"name":"x","version":"1","repository":"https://example.com/x"}`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.RepositoryURL != "https://example.com/x" {
		t.Fatalf("repo=%q", got.RepositoryURL)
	}
}

func TestParseManifestAuthorObjectForm(t *testing.T) {
	body := []byte(`{"name":"x","version":"1","author":{"name":"Alice","email":"a@x"}}`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Author != "Alice <a@x>" {
		t.Fatalf("author=%q", got.Author)
	}
}

func TestParseManifestBinShorthandUsesName(t *testing.T) {
	body := []byte(`{"name":"cool-tool","version":"1","bin":"./cli.js"}`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BinEntries) != 1 || got.BinEntries[0] != "cool-tool" {
		t.Fatalf("bin=%+v", got.BinEntries)
	}
}

func TestParseManifestBinShorthandScopedStripsScope(t *testing.T) {
	body := []byte(`{"name":"@scope/cool-tool","version":"1","bin":"./cli.js"}`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BinEntries) != 1 || got.BinEntries[0] != "cool-tool" {
		t.Fatalf("scoped bin shorthand=%+v", got.BinEntries)
	}
}

func TestParseManifestBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"name":"x","version":"1"}`)...)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.Name != "x" {
		t.Fatalf("name=%q", got.Name)
	}
}

func TestParseManifestEmpty(t *testing.T) {
	if _, err := ParseManifest(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseManifestMalformed(t *testing.T) {
	if _, err := ParseManifest([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksFlatAndScoped(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "node_modules")

	// Flat package: node_modules/chalk/package.json
	chalkDir := filepath.Join(root, "chalk")
	must(t, os.MkdirAll(chalkDir, 0o755))
	must(t, os.WriteFile(filepath.Join(chalkDir, "package.json"),
		[]byte(`{"name":"chalk","version":"5.3.0","license":"MIT"}`), 0o644))

	// Scoped package: node_modules/@vendor/cli/package.json
	scopedDir := filepath.Join(root, "@vendor", "cli")
	must(t, os.MkdirAll(scopedDir, 0o755))
	must(t, os.WriteFile(filepath.Join(scopedDir, "package.json"),
		[]byte(`{"name":"@vendor/cli","version":"1.0.0","scripts":{"postinstall":"node x.js"}}`), 0o644))

	// Package without manifest — must be skipped.
	broken := filepath.Join(root, "broken")
	must(t, os.MkdirAll(broken, 0o755))

	// Hidden dir — must be skipped.
	must(t, os.MkdirAll(filepath.Join(root, ".cache"), 0o755))

	c := &fileCollector{
		roots:    []string{root},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 packages, got %d: %+v", len(got), got)
	}

	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	chalk := byName["chalk"]
	if chalk.IsScopedPackage || chalk.HasInstallScripts {
		t.Fatalf("chalk row wrong: %+v", chalk)
	}
	if chalk.License != "MIT" || chalk.HasNoLicense {
		t.Fatal("chalk has MIT license")
	}

	vendor := byName["@vendor/cli"]
	if !vendor.IsScopedPackage {
		t.Fatal("@vendor/cli must flag scoped")
	}
	if !vendor.HasInstallScripts {
		t.Fatalf("postinstall must flag: %+v", vendor)
	}
	if vendor.InstallPrefix != root {
		t.Fatalf("install_prefix=%q", vendor.InstallPrefix)
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []string{"/nope-npm"},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortPackages ---------------------------------------------------

func TestSortPackagesDeterministic(t *testing.T) {
	in := []Package{
		{Name: "z", Version: "1.0.0"},
		{Name: "a", Version: "2.0.0"},
		{Name: "a", Version: "1.0.0"},
	}
	SortPackages(in)
	if in[0].Name != "a" || in[0].Version != "1.0.0" {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- Spot-check that the curated install-script set is included -----

func TestInstallScriptNamesIncludesAll(t *testing.T) {
	want := []string{"preinstall", "install", "postinstall", "prepare"}
	got := strings.Join(InstallScriptNames(), ",")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("InstallScriptNames missing %q (got %q)", w, got)
		}
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
