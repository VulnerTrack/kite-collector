package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestPerlModulePathsCanonicalizesVersionedDirectoryAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native ownership adapter requires Unix paths")
	}
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("Perl unavailable")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "5.38.2")
	alias := filepath.Join(root, "5.38")
	require.NoError(t, os.Mkdir(dir, 0o700))
	file := filepath.Join(dir, "OwnershipFixture.pm")
	require.NoError(t, os.WriteFile(file, []byte("die 'must not load the inspected module';\n"), 0o600))
	require.NoError(t, os.Symlink(dir, alias))
	t.Setenv("PERL5LIB", alias+string(os.PathListSeparator)+dir)
	out, err := runWithLimits(context.Background(), perl, "-e", perlModulePaths, "--", "OwnershipFixture")
	require.NoError(t, err)
	var paths map[string][]string
	require.NoError(t, json.Unmarshal(out, &paths))
	realFile, err := filepath.EvalSymlinks(file)
	require.NoError(t, err)
	assert.Equal(t, []string{realFile}, paths["OwnershipFixture"])
}

func TestCPANCommonOwnerWithoutSourceRequiresTheSameBinaryVersion(t *testing.T) {
	first := &model.InstalledSoftware{SoftwareName: "perl-base", Version: "5.38.2-3"}
	second := *first
	paths := []string{"/a.pm", "/b.pm"}
	owners := map[string]string{"/a.pm": "first", "/b.pm": "second"}
	packages := map[string]*model.InstalledSoftware{"first": first, "second": &second}
	assert.Same(t, first, commonModuleOwner(paths, owners, packages))
	second.Version = "5.38.2-4"
	assert.Nil(t, commonModuleOwner(paths, owners, packages))
	second.Version = first.Version
	second.SoftwareName = "perl-modules-5.38"
	assert.Nil(t, commonModuleOwner(paths, owners, packages))
}

func TestCPANCommonOwnerRequiresEveryCopyToHaveTheSameSourceVersion(t *testing.T) {
	base := model.InstalledSoftware{
		SoftwareName: "perl-base", Version: "5.38.2-3+b1", SourcePackage: "perl", SourceVersion: "5.38.2-3",
	}
	for _, tt := range []struct {
		name   string
		other  *model.InstalledSoftware
		owners map[string]string
		want   bool
	}{
		{
			name: "same native binary", other: &base,
			owners: map[string]string{"/a.pm": "first", "/b.pm": "second"}, want: true,
		},
		{
			name: "different binaries with one exact installed source",
			other: &model.InstalledSoftware{
				SoftwareName: "perl-modules-5.38", Version: "5.38.2-3", SourcePackage: "perl", SourceVersion: "5.38.2-3",
			},
			owners: map[string]string{"/a.pm": "first", "/b.pm": "second"}, want: true,
		},
		{
			name: "different source revision",
			other: &model.InstalledSoftware{
				SoftwareName: "perl-modules-5.38", Version: "5.38.2-4", SourcePackage: "perl", SourceVersion: "5.38.2-4",
			},
			owners: map[string]string{"/a.pm": "first", "/b.pm": "second"},
		},
		{
			name: "different source product",
			other: &model.InstalledSoftware{
				SoftwareName: "custom-perl", Version: "5.38.2-3", SourcePackage: "custom", SourceVersion: "5.38.2-3",
			},
			owners: map[string]string{"/a.pm": "first", "/b.pm": "second"},
		},
		{
			name: "unowned shadow copy", other: &base, owners: map[string]string{"/a.pm": "first"},
		},
		{
			name: "ambiguous file ownership", other: &base, owners: map[string]string{"/a.pm": "first", "/b.pm": ""},
		},
		{
			name: "owner absent from installed inventory", owners: map[string]string{"/a.pm": "first", "/b.pm": "second"},
		},
		{
			name:   "source version missing",
			other:  &model.InstalledSoftware{SoftwareName: "perl-modules-5.38", Version: "5.38.2-3", SourcePackage: "perl"},
			owners: map[string]string{"/a.pm": "first", "/b.pm": "second"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := commonModuleOwner([]string{"/a.pm", "/b.pm"}, tt.owners,
				map[string]*model.InstalledSoftware{"first": &base, "second": tt.other})
			if tt.want {
				assert.Same(t, &base, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestCPANLiteralPathsRejectsIncompleteOrOversizedSets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Module.pm")
	assert.Equal(t, []string{path}, literalModulePaths([]string{path, path}))
	for _, invalid := range []string{"relative.pm", path + "*", path + "\n", path + "\x00", path + ".txt"} {
		assert.Nil(t, literalModulePaths([]string{path, invalid}))
	}
	assert.Nil(t, literalModulePaths(make([]string, maxModulePaths+1)))
	assert.Nil(t, commonModuleOwner(nil, nil, nil))
}

func TestCPANOwnershipBatchesCanonicalCopiesAndPreservesObservedVersion(t *testing.T) {
	modules := map[string][]string{}
	var input string
	for i := range 60 {
		name := fmt.Sprintf("Fixture%d", i)
		modules[name] = []string{fmt.Sprintf("/base/%s.pm", name), fmt.Sprintf("/modules/%s.pm", name)}
		input += name + "\tundef\n"
	}
	raw, err := json.Marshal(modules)
	require.NoError(t, err)
	fakeToolOnPath(t, "perl", "cat <<'EOF'\n"+string(raw)+"\nEOF\n")
	fakeToolOnPath(t, "dpkg-query", `case "$1" in
-W) printf 'perl-base\t5.38.2-3+b1\tamd64\tperl\t5.38.2-3\t\tPerl\tinstalled\nperl-modules-5.38\t5.38.2-3\tall\tperl\t5.38.2-3\t\tPerl modules\tinstalled\n' ;;
-S) shift 2
    [ "$#" -le 100 ] || exit 2
    for path in "$@"; do
      case "$path" in
        /base/*) printf 'perl-base: %s\n' "$path" ;;
        /modules/*) printf 'perl-modules-5.38: %s\n' "$path" ;;
      esac
    done ;;
esac`)
	result := ParseCPANOutput(input)
	enrichCPANOwnershipWith(context.Background(), result, "perl")
	require.Len(t, result.Items, 60)
	for _, item := range result.Items {
		require.NotNil(t, item.PackageOwner, item.SoftwareName)
		assert.Empty(t, item.Version)
		assert.Equal(t, "cpan", item.PackageManager)
		assert.Equal(t, "perl", item.PackageOwner.SourcePackage)
		assert.Equal(t, "5.38.2-3", item.PackageOwner.SourceVersion)
		assert.Equal(t, item.InstallPath, item.PackageOwner.File)
	}
}
