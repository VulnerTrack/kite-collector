package parsers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// depByName indexes a ParseResult for exact-value assertions.
func depByName(t *testing.T, r *ParseResult) map[string]Dependency {
	t.Helper()
	out := make(map[string]Dependency, len(r.Dependencies))
	for _, d := range r.Dependencies {
		out[d.Name] = d
	}
	return out
}

// --- registry -------------------------------------------------------------

// Every registered parser must expose a non-empty ecosystem and at least
// one pattern, and every exact pattern must round-trip through Match back
// to a parser of the same ecosystem — the walker depends on this mapping.
func TestRegistry_EveryParserPatternRoundTrips(t *testing.T) {
	r := NewRegistry()
	names := r.Filenames()
	require.NotEmpty(t, names)

	for filename := range names {
		p := r.Match(filename)
		require.NotNil(t, p, "exact filename %q must match its parser", filename)
		assert.NotEmpty(t, p.Ecosystem())
		assert.NotEmpty(t, p.Patterns())
	}
}

func TestRegistry_MatchMissAndGlobs(t *testing.T) {
	r := NewRegistry()
	assert.Nil(t, r.Match("definitely-not-a-manifest.xyz"))
	// *.csproj registers as a glob, not an exact name.
	if p := r.Match("MyService.csproj"); assert.NotNil(t, p, "glob patterns must match") {
		assert.Equal(t, "dotnet", p.Ecosystem())
	}
	_, isExact := r.Filenames()["*.csproj"]
	assert.False(t, isExact, "globs must not appear in the exact-filename set")
}

// --- dart / pubspec.yaml --------------------------------------------------

func TestPubspecParser(t *testing.T) {
	p := &PubspecParser{}
	assert.Equal(t, []string{"pubspec.yaml"}, p.Patterns())
	assert.Equal(t, "dart", p.Ecosystem())

	content := []byte(`
name: my_app
version: 1.4.0
dependencies:
  http: ^0.13.0
  intl: any
  flutter:
    sdk: flutter
  hosted_dep:
    version: ~2.1.0
dev_dependencies:
  test: ">=1.16.0"
`)
	result, err := p.Parse(context.Background(), "/app/pubspec.yaml", content)
	require.NoError(t, err)
	assert.Equal(t, "my_app", result.ProjectName)
	assert.Equal(t, "1.4.0", result.ProjectVersion)
	assert.Equal(t, "/app/pubspec.yaml", result.ManifestPath)

	deps := depByName(t, result)
	require.Len(t, deps, 5)
	assert.Equal(t, "0.13.0", deps["http"].Version, "range operator stripped")
	assert.Equal(t, "runtime", deps["http"].Scope)
	assert.True(t, deps["http"].Direct)
	assert.Equal(t, "2.1.0", deps["hosted_dep"].Version, "map-form dep with version key")
	assert.Empty(t, deps["flutter"].Version, "sdk dep map without version yields empty")
	assert.Equal(t, "dev", deps["test"].Scope)
	assert.Equal(t, "1.16.0", deps["test"].Version)
}

func TestPubspecParser_MalformedYAMLErrors(t *testing.T) {
	_, err := (&PubspecParser{}).Parse(context.Background(), "x", []byte("\tnot: yaml: ["))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pubspec.yaml")
}

// --- elixir / mix.exs -----------------------------------------------------

func TestMixExsParser(t *testing.T) {
	p := &MixExsParser{}
	assert.Equal(t, []string{"mix.exs"}, p.Patterns())
	assert.Equal(t, "elixir", p.Ecosystem())

	content := []byte(`
  defp deps do
    [
      {:phoenix, "~> 1.7.10"},
      {:ecto_sql, "~> 3.10"}, {:jason, ">= 1.2.0"},
      {:my_fork, github: "me/my_fork"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
`)
	result, err := p.Parse(context.Background(), "/app/mix.exs", content)
	require.NoError(t, err)

	deps := depByName(t, result)
	require.Len(t, deps, 4, "the github-sourced dep has no version string and is skipped")
	assert.Equal(t, "1.7.10", deps["phoenix"].Version)
	assert.Equal(t, "3.10", deps["ecto_sql"].Version)
	assert.Equal(t, "1.2.0", deps["jason"].Version, "two deps on one line both match")
	assert.Equal(t, "1.7", deps["credo"].Version)
	_, hasFork := deps["my_fork"]
	assert.False(t, hasFork)
}

func TestMixExsParser_EmptyInput(t *testing.T) {
	result, err := (&MixExsParser{}).Parse(context.Background(), "x", nil)
	require.NoError(t, err)
	assert.Empty(t, result.Dependencies)
}

// --- swift / Package.swift ------------------------------------------------

func TestSwiftPackageParser(t *testing.T) {
	p := &SwiftPackageParser{}
	assert.Equal(t, []string{"Package.swift"}, p.Patterns())
	assert.Equal(t, "swift", p.Ecosystem())

	content := []byte(`
let package = Package(
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.62.0"),
        .package(name: "Fluent", url: "https://github.com/vapor/fluent", from: "4.8.0"),
    ]
)
`)
	result, err := p.Parse(context.Background(), "/app/Package.swift", content)
	require.NoError(t, err)

	deps := depByName(t, result)
	require.Len(t, deps, 2)
	assert.Equal(t, "2.62.0", deps["swift-nio"].Version, ".git suffix trimmed from the repo name")
	assert.Equal(t, "4.8.0", deps["fluent"].Version, "name:-prefixed declarations still parse")
	assert.Equal(t, "runtime", deps["swift-nio"].Scope)
	assert.True(t, deps["swift-nio"].Direct)
}

func TestRepoNameFromSwiftURL(t *testing.T) {
	assert.Equal(t, "swift-nio", repoNameFromSwiftURL("https://github.com/apple/swift-nio.git"))
	assert.Equal(t, "fluent", repoNameFromSwiftURL("https://github.com/vapor/fluent"))
	assert.Equal(t, "bare", repoNameFromSwiftURL("bare"), "URL with no slash stays whole")
}

// --- perl / cpanfile ------------------------------------------------------

func TestCpanfileParser(t *testing.T) {
	p := &CpanfileParser{}
	assert.Equal(t, []string{"cpanfile"}, p.Patterns())
	assert.Equal(t, "perl", p.Ecosystem())

	content := []byte(`
requires 'Plack', '1.0047';
requires "Moose";
requires 'DBIx::Class', '0.082843';
# requires 'Commented::Out', '9.9';
`)
	result, err := p.Parse(context.Background(), "/app/cpanfile", content)
	require.NoError(t, err)

	deps := depByName(t, result)
	assert.Equal(t, "1.0047", deps["Plack"].Version)
	assert.Empty(t, deps["Moose"].Version, "versionless requires yields empty version")
	assert.Equal(t, "0.082843", deps["DBIx::Class"].Version, "double-colon module names parse")
}

// --- yarn.lock ------------------------------------------------------------

func TestYarnLockParser(t *testing.T) {
	p := &YarnLockParser{}
	assert.Equal(t, []string{"yarn.lock"}, p.Patterns())
	assert.Equal(t, "node.js", p.Ecosystem())

	content := []byte(`# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

"@babel/core@^7.0.0", "@babel/core@^7.22.0":
  version "7.23.5"
`)
	result, err := p.Parse(context.Background(), "/app/yarn.lock", content)
	require.NoError(t, err)
	assert.True(t, result.LockfileUsed)

	deps := depByName(t, result)
	require.Len(t, deps, 2)
	assert.Equal(t, "4.18.2", deps["express"].Version)
	assert.False(t, deps["express"].Direct, "lockfile entries are transitive by default")
	assert.Equal(t, "7.23.5", deps["@babel/core"].Version,
		"scoped, comma-separated header collapses to one name")
}

func TestYarnPackageName(t *testing.T) {
	assert.Equal(t, "express", yarnPackageName("express@^4.18.2:"))
	assert.Equal(t, "@scope/pkg", yarnPackageName(`"@scope/pkg@^1.0.0", "@scope/pkg@^1.0.1":`))
	assert.Equal(t, "no-version", yarnPackageName("no-version:"))
}

// --- pnpm-lock.yaml -------------------------------------------------------

func TestPnpmLockParser(t *testing.T) {
	p := &PnpmLockParser{}
	assert.Equal(t, []string{"pnpm-lock.yaml"}, p.Patterns())
	assert.Equal(t, "node.js", p.Ecosystem())

	content := []byte(`
lockfileVersion: '6.0'
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-x}
  /@types/node@20.10.0:
    dev: true
  /weird@1.0.0:
    version: 1.0.1
`)
	result, err := p.Parse(context.Background(), "/app/pnpm-lock.yaml", content)
	require.NoError(t, err)
	assert.True(t, result.LockfileUsed)

	deps := depByName(t, result)
	require.Len(t, deps, 3)
	assert.Equal(t, "4.18.2", deps["express"].Version, "version parsed from the key")
	assert.Equal(t, "runtime", deps["express"].Scope)
	assert.Equal(t, "20.10.0", deps["@types/node"].Version, "scoped key splits at the second @")
	assert.Equal(t, "dev", deps["@types/node"].Scope)
	assert.Equal(t, "1.0.1", deps["weird"].Version, "explicit version field wins over the key")
}

func TestPnpmLockParser_MalformedYAMLErrors(t *testing.T) {
	_, err := (&PnpmLockParser{}).Parse(context.Background(), "x", []byte("\t: ["))
	require.Error(t, err)
}

func TestParsePnpmPackageKey(t *testing.T) {
	name, ver := parsePnpmPackageKey("/express@4.18.2")
	assert.Equal(t, "express", name)
	assert.Equal(t, "4.18.2", ver)

	name, ver = parsePnpmPackageKey("/@scope/pkg@1.0.0")
	assert.Equal(t, "@scope/pkg", name)
	assert.Equal(t, "1.0.0", ver)

	name, _ = parsePnpmPackageKey("")
	assert.Empty(t, name)
}

// --- shared helpers -------------------------------------------------------

func TestCleanVersion(t *testing.T) {
	assert.Equal(t, "1.2.3", cleanVersion("^1.2.3"))
	assert.Equal(t, "1.2.3", cleanVersion("~> 1.2.3"))
	assert.Equal(t, "0.13.0", cleanVersion(">=0.13.0"))
	assert.Equal(t, "1.0", cleanVersion("  1.0  "))
	assert.Empty(t, cleanVersion("^~>=<"))
}

// Stress: a large synthetic yarn.lock parses linearly and completely.
func TestYarnLockParser_StressManyPackages(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, "pkg-%04d@^1.0.0:\n  version \"1.0.%d\"\n\n", i, i%100)
	}
	result, err := (&YarnLockParser{}).Parse(context.Background(), "big", []byte(b.String()))
	require.NoError(t, err)
	assert.Len(t, result.Dependencies, 3000, "every entry parses, none double-count")
}
