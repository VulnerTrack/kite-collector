package software

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// buildNpmFixture lays out a node_modules tree exercising every case NpmScan
// must handle and returns the root to scan.
func buildNpmFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")

	// top-level package, string author + string license
	writeFile(t, filepath.Join(nm, "lodash", "package.json"),
		`{"name":"lodash","version":"4.17.21","author":"John Doe <j@e.com> (http://x)","license":"MIT","description":"utils","homepage":"http://lodash.com"}`)
	// scoped package, object author + object license
	writeFile(t, filepath.Join(nm, "@scope", "pkg", "package.json"),
		`{"name":"@scope/pkg","version":"1.0.0","author":{"name":"Acme","email":"a@b.c"},"license":{"type":"Apache-2.0"}}`)
	// nested (transitive) package under a package's own node_modules
	writeFile(t, filepath.Join(nm, "lodash", "node_modules", "nested", "package.json"),
		`{"name":"nested","version":"2.0.0","license":[{"type":"BSD"}]}`)
	// stray package.json inside a package's subtree — NOT an installed package
	writeFile(t, filepath.Join(nm, "lodash", "lib", "package.json"),
		`{"name":"lodash-subpath","version":"9.9.9"}`)
	// duplicate (name, version) at another install location — same tarball,
	// identical manifest — must dedupe to a single item
	writeFile(t, filepath.Join(nm, "dup", "package.json"),
		`{"name":"lodash","version":"4.17.21","author":"John Doe <j@e.com> (http://x)","license":"MIT"}`)
	// project-root package.json (not under node_modules) — ignored
	writeFile(t, filepath.Join(root, "package.json"),
		`{"name":"my-project","version":"0.0.0"}`)
	return root
}

func TestNpmScan_Collect(t *testing.T) {
	root := buildNpmFixture(t)
	s := NewNpmScan()
	s.roots = []string{root}

	res, err := s.Collect(context.Background())
	require.NoError(t, err)

	names := map[string]string{} // name -> version
	vendors := map[string]string{}
	for _, it := range res.Items {
		assert.Equal(t, "npm", it.PackageManager)
		assert.NotEmpty(t, it.CPE23)
		names[it.SoftwareName] = it.Version
		vendors[it.SoftwareName] = it.Vendor
	}

	assert.Len(t, res.Items, 3, "distinct installed packages: lodash, @scope/pkg, nested")
	assert.Equal(t, "4.17.21", names["lodash"])
	assert.Equal(t, "1.0.0", names["@scope/pkg"])
	assert.Equal(t, "2.0.0", names["nested"])
	assert.NotContains(t, names, "lodash-subpath", "stray subtree package.json ignored")
	assert.NotContains(t, names, "my-project", "project-root package.json ignored")

	assert.Equal(t, "John Doe", vendors["lodash"], "author string decorations stripped")
	assert.Equal(t, "Acme", vendors["@scope/pkg"], "author object name extracted")
}

func TestNpmScan_MaxPackagesCap(t *testing.T) {
	root := buildNpmFixture(t)
	s := NewNpmScan()
	s.roots = []string{root}
	s.maxPackages = 1

	res, err := s.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, res.Items, 1, "walk stops at the cap")
}

func TestNpmScan_ContextCancelled(t *testing.T) {
	root := buildNpmFixture(t)
	s := NewNpmScan()
	s.roots = []string{root}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := s.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, res.Items, "cancelled context yields nothing")
}

func TestParseNpmManifest(t *testing.T) {
	cases := []struct {
		name        string
		json        string
		wantOK      bool
		wantName    string
		wantAuthor  string
		wantLicense string
	}{
		{"string author + license", `{"name":"a","version":"1","author":"Jane <e> (u)","license":"MIT"}`, true, "a", "Jane", "MIT"},
		{"object author + license", `{"name":"b","version":"1","author":{"name":"Org"},"license":{"type":"ISC"}}`, true, "b", "Org", "ISC"},
		{"array license", `{"name":"c","version":"1","license":[{"type":"BSD"},{"type":"MIT"}]}`, true, "c", "", "BSD"},
		{"no author/license", `{"name":"d","version":"1"}`, true, "d", "", ""},
		{"missing name", `{"version":"1"}`, false, "", "", ""},
		{"invalid json", `{not json`, false, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := parseNpmManifest([]byte(c.json))
			assert.Equal(t, c.wantOK, ok)
			if !c.wantOK {
				return
			}
			assert.Equal(t, c.wantName, m.Name)
			assert.Equal(t, c.wantAuthor, m.Author)
			assert.Equal(t, c.wantLicense, m.License)
		})
	}
}

func TestIsNodeModulesPackageDir(t *testing.T) {
	assert.True(t, isNodeModulesPackageDir(filepath.FromSlash("/a/node_modules/lodash")))
	assert.True(t, isNodeModulesPackageDir(filepath.FromSlash("/a/node_modules/@scope/pkg")))
	assert.False(t, isNodeModulesPackageDir(filepath.FromSlash("/a/node_modules/lodash/lib")))
	assert.False(t, isNodeModulesPackageDir(filepath.FromSlash("/a/project")))
	assert.False(t, isNodeModulesPackageDir(filepath.FromSlash("/a/@scope/pkg")), "@scope not under node_modules")
}

func TestNpmScan_Available(t *testing.T) {
	t.Run("node on PATH", func(t *testing.T) {
		s := NewNpmScan()
		s.lookPath = func(bin string) (string, error) {
			if bin == "node" {
				return "/usr/bin/node", nil
			}
			return "", assert.AnError
		}
		s.statDir = func(string) bool { return false }
		s.userHome = func() (string, error) { return "", assert.AnError }
		assert.True(t, s.Available())
	})

	t.Run("no node but global dir exists", func(t *testing.T) {
		s := NewNpmScan()
		s.lookPath = func(string) (string, error) { return "", assert.AnError }
		s.statDir = func(d string) bool { return d == "/usr/lib/node_modules" }
		s.userHome = func() (string, error) { return "", assert.AnError }
		assert.True(t, s.Available())
	})

	t.Run("no node anywhere", func(t *testing.T) {
		s := NewNpmScan()
		s.lookPath = func(string) (string, error) { return "", assert.AnError }
		s.statDir = func(string) bool { return false }
		s.userHome = func() (string, error) { return "/home/x", nil }
		assert.False(t, s.Available())
	})
}
