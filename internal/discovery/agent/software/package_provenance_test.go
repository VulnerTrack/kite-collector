package software

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDpkgSourceVersionAndInstalledStatus(t *testing.T) {
	r := ParseDpkgOutput("libdemo1\t2:4.2-3+b1\tamd64\tdemo\t2:4.2-3\thttps://example.org/demo\tDemo library\tinstalled\n" +
		"removed\t1.0\tall\tremoved\t1.0\t\tOld package\tconfig-files\n")
	require.Len(t, r.Items, 1)
	p := r.Items[0]
	assert.Equal(t, "2:4.2-3+b1", p.Version)
	assert.Equal(t, "demo", p.SourcePackage)
	assert.Equal(t, "2:4.2-3", p.SourceVersion)
	assert.Equal(t, "https://example.org/demo", p.Homepage)
	assert.Equal(t, "Demo library", p.Description)
}

func TestCPANOwnershipUsesInstalledNativeVersionAndPreservesModules(t *testing.T) {
	fakeToolOnPath(t, "perl", `printf '%s' '{"Git::I18N":"/usr/share/perl5/Git/I18N.pm","Private::Thing":"/opt/perl/Private/Thing.pm","Shared::File":"/usr/share/perl5/Shared/File.pm"}'`)
	fakeToolOnPath(t, "dpkg-query", `case "$1" in
-W) printf 'git\t1:2.43.0-1ubuntu7\tamd64\tgit\t1:2.43.0-1ubuntu7\thttps://git-scm.com\tGit\tinstalled\n' ;;
-S) printf 'git: /usr/share/perl5/Git/I18N.pm\nfirst, second: /usr/share/perl5/Shared/File.pm\n'; exit 1 ;;
esac`)
	r := ParseCPANOutput("Git::I18N\tundef\nPrivate::Thing\t9.2\nShared::File\t1.0\n")
	enrichCPANOwnershipWith(context.Background(), r, "perl")
	require.Len(t, r.Items, 3)
	git := r.Items[0]
	require.NotNil(t, git.PackageOwner)
	assert.Equal(t, "", git.Version)
	assert.Equal(t, "cpan", git.PackageManager)
	assert.Equal(t, "git", git.PackageOwner.Name)
	assert.Equal(t, "1:2.43.0-1ubuntu7", git.PackageOwner.Version)
	assert.Equal(t, git.InstallPath, git.PackageOwner.File)
	assert.Nil(t, r.Items[1].PackageOwner)
	assert.Equal(t, "9.2", r.Items[1].Version)
	assert.Nil(t, r.Items[2].PackageOwner)
}

func TestCPANOwnershipFailureDoesNotDropInventory(t *testing.T) {
	fakeToolOnPath(t, "dpkg-query", "exit 2")
	r := ParseCPANOutput("File::Spec::Unix\t3.88\n")
	enrichCPANOwnershipWith(context.Background(), r, "perl")
	require.Len(t, r.Items, 1)
	assert.Nil(t, r.Items[0].PackageOwner)
	assert.Equal(t, "3.88", r.Items[0].Version)
}

func TestDpkgFileOwnershipRejectsAmbiguityAndUnrequestedPaths(t *testing.T) {
	wanted := map[string]bool{"/a.pm": true, "/b.pm": true, "/c.pm": true}
	got := parseDpkgFileOwners("pkg:amd64: /a.pm\npkg: /b.pm\nother: /b.pm\npkg: /b.pm\npkg: /outside.pm\ndiversion by pkg from: /c.pm\npkg: /c.pm\n", wanted)
	assert.Equal(t, "pkg:amd64", got["/a.pm"])
	assert.Empty(t, got["/b.pm"])
	assert.Empty(t, got["/c.pm"])
	assert.NotContains(t, got, "/outside.pm")
}

func TestPerlFileLookupDoesNotExecuteModule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native ownership adapter requires Unix paths")
	}
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("Perl unavailable")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "OwnershipFixture.pm"), []byte("die 'must never execute';\n"), 0o600))
	t.Setenv("PERL5LIB", dir)
	out, err := runWithLimits(context.Background(), perl, "-e", perlModulePaths, "--", "OwnershipFixture")
	require.NoError(t, err)
	assert.Contains(t, string(out), "OwnershipFixture.pm")
	// A shadowed copy might have another module version or native owner.
	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, "OwnershipFixture.pm"), []byte("die 'shadowed module';\n"), 0o600))
	t.Setenv("PERL5LIB", dir+string(os.PathListSeparator)+other)
	out, err = runWithLimits(context.Background(), perl, "-e", perlModulePaths, "--", "OwnershipFixture")
	require.NoError(t, err)
	assert.JSONEq(t, "{}", string(out))
}

func TestCPANInterpreterRequiresKnownShebang(t *testing.T) {
	dir := fakeToolOnPath(t, "cpan", "exit 0")
	assert.Empty(t, cpanInterpreter(), "a shell wrapper does not identify Perl's search path")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpan"), []byte("#!/usr/bin/perl\n"), 0o700))
	assert.Equal(t, "/usr/bin/perl", cpanInterpreter())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpan"), []byte("#!/usr/bin/perl -I/other\n"), 0o700))
	assert.Empty(t, cpanInterpreter())
}

func TestCPANInterpreterConfinesSymlinkToExecutableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.Mkdir(bin, 0o700))
	t.Setenv("PATH", bin)
	script := []byte("#!/usr/bin/perl\n")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "cpan-versioned"), script, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "outside"), script, 0o700))
	path := filepath.Join(bin, "cpan")
	for _, tc := range []struct {
		name, target, want string
	}{
		{"inside", "cpan-versioned", "/usr/bin/perl"},
		{"relative escape", "../outside", ""},
		{"absolute escape", filepath.Join(root, "outside"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.Symlink(tc.target, path))
			defer func() { require.NoError(t, os.Remove(path)) }()
			assert.Equal(t, tc.want, cpanInterpreter())
		})
	}
}
