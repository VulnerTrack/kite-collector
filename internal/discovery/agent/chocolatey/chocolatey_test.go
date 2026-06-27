package chocolatey

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("<package/>"))
	b := HashContents([]byte("<package/>"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsPrereleaseVersion(t *testing.T) {
	hit := []string{
		"1.0.0-beta",
		"2.45.0-rc.1",
		"3.0.0-dev",
		"v4.0.0-alpha",
		"V0.1.0-pre+build.42",
	}
	for _, v := range hit {
		if !IsPrereleaseVersion(v) {
			t.Fatalf("%q must flag prerelease", v)
		}
	}
	miss := []string{
		"1.0.0",
		"2.45.0",
		"v3.0.0",
		"4.0.0+build.42", // build metadata, no prerelease
		"",
	}
	for _, v := range miss {
		if IsPrereleaseVersion(v) {
			t.Fatalf("%q must NOT flag prerelease", v)
		}
	}
}

func TestIsFromNonDefaultSource(t *testing.T) {
	defaults := []string{
		"https://community.chocolatey.org/api/v2/",
		"https://chocolatey.org/api/v2/",
		"HTTPS://CHOCOLATEY.ORG/api/v2/",
		"https://push.chocolatey.org/",
		"",
	}
	for _, s := range defaults {
		if IsFromNonDefaultSource(s) {
			t.Fatalf("%q must NOT flag non-default", s)
		}
	}
	external := []string{
		"https://proget.internal.corp/chocolatey/",
		"https://artifactory.example.com/api/nuget/",
		"http://attacker.local/nuget/",
	}
	for _, s := range external {
		if !IsFromNonDefaultSource(s) {
			t.Fatalf("%q must flag non-default", s)
		}
	}
}

func TestEncodeDependencies(t *testing.T) {
	if EncodeDependencies(nil) != "[]" {
		t.Fatal("nil")
	}
	got := EncodeDependencies([]Dependency{{ID: "chocolatey-core.extension", Version: "1.4.0"}})
	if !strings.Contains(got, `"id":"chocolatey-core.extension"`) {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateHasNoLicenseMetadata(t *testing.T) {
	p := Package{}
	AnnotateSecurity(&p)
	if !p.HasNoLicenseMetadata {
		t.Fatal("empty license fields must flag")
	}

	p2 := Package{LicenseURL: "https://opensource.org/licenses/MIT"}
	AnnotateSecurity(&p2)
	if p2.HasNoLicenseMetadata {
		t.Fatal("licenseUrl set must clear flag")
	}

	p3 := Package{LicenseExpression: "MIT"}
	AnnotateSecurity(&p3)
	if p3.HasNoLicenseMetadata {
		t.Fatal("license expression set must clear flag")
	}
}

func TestAnnotatePrereleaseAndNonDefault(t *testing.T) {
	p := Package{
		PackageVersion: "2.0.0-beta",
		SourceURL:      "https://proget.internal.corp/chocolatey/",
	}
	AnnotateSecurity(&p)
	if !p.IsPrerelease {
		t.Fatal("prerelease must flag")
	}
	if !p.IsFromNonDefaultSource {
		t.Fatal("non-default source must flag")
	}
}

// -- ParseNuspec typical (flat dependencies) -------------------------

func TestParseNuspecTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>git</id>
    <version>2.45.0</version>
    <title>Git</title>
    <authors>Git Development Community</authors>
    <owners>chocolatey-community</owners>
    <projectUrl>https://git-scm.com/</projectUrl>
    <licenseUrl>https://opensource.org/licenses/GPL-2.0</licenseUrl>
    <description>Git is a distributed VCS.</description>
    <tags>git scm vcs</tags>
    <dependencies>
      <dependency id="git.install" version="2.45.0" />
      <dependency id="chocolatey-core.extension" version="1.4.0" />
    </dependencies>
  </metadata>
</package>`)
	got, err := ParseNuspec(body, `C:\ProgramData\chocolatey\lib\git\git.nuspec`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.PackageID != "git" || got.PackageVersion != "2.45.0" {
		t.Fatalf("id/version: %+v", got)
	}
	if got.LicenseURL == "" {
		t.Fatal("licenseUrl must propagate")
	}
	if got.HasNoLicenseMetadata {
		t.Fatal("licenseUrl set must clear flag")
	}
	if len(got.Dependencies) != 2 || got.DependencyCount != 2 {
		t.Fatalf("dependencies: %+v", got.Dependencies)
	}
	if got.IsPrerelease {
		t.Fatal("2.45.0 must NOT flag prerelease")
	}
}

// -- ParseNuspec license expression (modern NuGet 4.9+) --------------

func TestParseNuspecLicenseExpression(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<package><metadata>
  <id>foo</id>
  <version>1.0.0</version>
  <license type="expression">MIT</license>
</metadata></package>`)
	got, err := ParseNuspec(body, "x.nuspec")
	if err != nil {
		t.Fatal(err)
	}
	if got.LicenseExpression != "MIT" {
		t.Fatalf("license_expression=%q", got.LicenseExpression)
	}
	if got.HasNoLicenseMetadata {
		t.Fatal("expression set must clear flag")
	}
}

// -- ParseNuspec dependency groups (per-targetFramework) -------------

func TestParseNuspecDependencyGroups(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<package><metadata>
  <id>multi-tfm</id>
  <version>1.0.0</version>
  <dependencies>
    <group targetFramework="net6.0">
      <dependency id="dep-net6" version="1.0.0" />
    </group>
    <group targetFramework="net8.0">
      <dependency id="dep-net8" version="2.0.0" />
    </group>
  </dependencies>
</metadata></package>`)
	got, err := ParseNuspec(body, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Dependencies) != 2 {
		t.Fatalf("group flatten broken: %+v", got.Dependencies)
	}
}

// -- ParseNuspec BOM tolerance --------------------------------------

func TestParseNuspecBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`<package><metadata><id>x</id><version>1</version></metadata></package>`)...)
	got, err := ParseNuspec(body, "x")
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.PackageID != "x" {
		t.Fatalf("id=%q", got.PackageID)
	}
}

func TestParseNuspecEmpty(t *testing.T) {
	if _, err := ParseNuspec(nil, "x"); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseNuspecMalformed(t *testing.T) {
	if _, err := ParseNuspec([]byte("not xml"), "x"); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksLibDirectories(t *testing.T) {
	tmp := t.TempDir()
	// lib/git/git.nuspec (canonical layout).
	gitDir := filepath.Join(tmp, "git")
	must(t, os.MkdirAll(gitDir, 0o755))
	must(t, os.WriteFile(filepath.Join(gitDir, "git.nuspec"), []byte(`<package><metadata>
<id>git</id><version>2.45.0</version>
<licenseUrl>https://opensource.org/licenses/GPL-2.0</licenseUrl>
</metadata></package>`), 0o644))

	// lib/foo/foo.nuspec with prerelease + no license.
	fooDir := filepath.Join(tmp, "foo")
	must(t, os.MkdirAll(fooDir, 0o755))
	must(t, os.WriteFile(filepath.Join(fooDir, "foo.nuspec"), []byte(`<package><metadata>
<id>foo</id><version>1.0.0-beta</version>
</metadata></package>`), 0o644))

	// lib/odd-name/some-other.nuspec (non-canonical filename — must
	// still discover via the *.nuspec fallback).
	oddDir := filepath.Join(tmp, "odd-name")
	must(t, os.MkdirAll(oddDir, 0o755))
	must(t, os.WriteFile(filepath.Join(oddDir, "some-other.nuspec"), []byte(`<package><metadata>
<id>odd-name</id><version>3.0.0</version>
<license type="expression">Apache-2.0</license>
</metadata></package>`), 0o644))

	// Hidden directory should be skipped.
	must(t, os.MkdirAll(filepath.Join(tmp, ".cache"), 0o755))

	c := &fileCollector{
		root:     tmp,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 packages, got %d: %+v", len(got), got)
	}

	byID := map[string]Package{}
	for _, p := range got {
		byID[p.PackageID] = p
	}

	git := byID["git"]
	if git.LicenseURL == "" || git.HasNoLicenseMetadata {
		t.Fatalf("git license broken: %+v", git)
	}
	foo := byID["foo"]
	if !foo.IsPrerelease || !foo.HasNoLicenseMetadata {
		t.Fatalf("foo flags wrong: %+v", foo)
	}
	odd := byID["odd-name"]
	if odd.LicenseExpression != "Apache-2.0" {
		t.Fatalf("odd license: %+v", odd)
	}
}

func TestFileCollectorMissingRootOK(t *testing.T) {
	c := &fileCollector{
		root:     "/nope-choco",
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
		{PackageID: "git", PackageVersion: "2.46.0"},
		{PackageID: "git", PackageVersion: "2.45.0"},
		{PackageID: "7zip", PackageVersion: "23.0.0"},
	}
	SortPackages(in)
	if in[0].PackageID != "7zip" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[1].PackageVersion != "2.45.0" {
		t.Fatalf("git order: in[1]=%+v in[2]=%+v", in[1], in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
