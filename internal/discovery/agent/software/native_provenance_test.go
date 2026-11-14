package software

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPKMetadataKeepsSourceSeparateFromVendor(t *testing.T) {
	jsonRecord := `[{"name":"libcrypto3","version":"3.5.5-r0","arch":"x86_64","origin":"openssl","url":"https://www.openssl.org/","license":"Apache-2.0","description":"Crypto library"}]`
	r, err := parseAPKJSON([]byte(jsonRecord))
	require.NoError(t, err)
	require.Len(t, r.Items, 1)
	p := r.Items[0]
	assert.Empty(t, p.Vendor)
	assert.Equal(t, "libcrypto3", p.SoftwareName)
	assert.Equal(t, "openssl", p.SourcePackage)
	assert.Equal(t, "3.5.5-r0", p.SourceVersion)
	assert.Equal(t, "https://www.openssl.org/", p.Homepage)
	assert.Equal(t, "Apache-2.0", p.License)
	assert.Contains(t, p.CPE23, ":*:libcrypto3:")

	dbRecord := "P:libcrypto3\nV:3.5.5-r0\nA:x86_64\no:openssl\nU:https://www.openssl.org/\nL:Apache-2.0\nT:Crypto library\nF:usr/lib\nR:libcrypto.so.3\n"
	legacy, err := parseAPKDatabase(strings.NewReader(dbRecord))
	require.NoError(t, err)
	require.Len(t, legacy.Items, 1)
	legacy.Items[0].ID = p.ID
	assert.Equal(t, p, legacy.Items[0])
}

func TestAPKStructuredCollectSelectsOnlyInstalledRecords(t *testing.T) {
	fakeToolOnPath(t, "apk", `test "$1" = query || exit 1
test "$2" = --installed || exit 2
printf '%s' '[{"name":"curl","version":"8.7.1-r0","arch":"x86_64","origin":"curl"}]'`)
	r, err := NewAPK().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, r.Items, 1)
	assert.Equal(t, "curl", r.Items[0].SourcePackage)
}

func TestAPKRejectsIncompleteMetadataInsteadOfReplacingInventory(t *testing.T) {
	for _, raw := range []string{"null", `{}`, `[{"name":"curl"}]`, `[`} {
		_, err := parseAPKJSON([]byte(raw))
		require.Error(t, err)
	}
	for _, raw := range []string{"P:curl\n", "P:curl\nP:other\nV:1\nA:all\n"} {
		_, err := parseAPKDatabase(strings.NewReader(raw))
		require.Error(t, err)
	}
	name, version := splitNameVersion("libfoo-2-tools-3.0_rc1-r7")
	assert.Equal(t, "libfoo-2-tools", name)
	assert.Equal(t, "3.0_rc1-r7", version)
}

func TestRPMUsesSourceRPMVersionAndMetadata(t *testing.T) {
	r := ParseRPMOutput("libfixture1\t2.0-3.fc42\tFedora Project\tx86_64\tfixture-source-1.9-2.fc42.src.rpm\thttps://example.org/fixture\tMIT\tA library\n")
	require.Len(t, r.Items, 1)
	p := r.Items[0]
	assert.Equal(t, "2.0-3.fc42", p.Version)
	assert.Equal(t, "Fedora Project", p.Vendor)
	assert.Equal(t, "fixture-source", p.SourcePackage)
	assert.Equal(t, "1.9-2.fc42", p.SourceVersion)
	assert.Equal(t, "https://example.org/fixture", p.Homepage)
	assert.Equal(t, "MIT", p.License)
	assert.Equal(t, "A library", p.Description)
	for _, filename := range []string{"(none)", "name.src.rpm", "a--1.src.rpm", "../a-1-2.src.rpm", "a-1-2.x86_64.rpm"} {
		name, version := rpmSource(filename)
		assert.Empty(t, name)
		assert.Empty(t, version)
	}
	name, version := rpmSource("LibFixture-3-2.0~rc1-1.nosrc.rpm")
	assert.Equal(t, "LibFixture-3", name)
	assert.Equal(t, "2.0~rc1-1", version)
}

// Run the compiled test in disposable APK 2 and APK 3 containers without network
// access. This verifies the command/installed-database formats, not a mocked CLI.
func TestAPKInstalledIntegration(t *testing.T) {
	if os.Getenv("KITE_TEST_NATIVE_APK") != "1" {
		t.Skip("requires disposable Alpine container")
	}
	r, err := NewAPK().Collect(context.Background())
	require.NoError(t, err)
	require.False(t, r.HasErrors())
	for _, item := range r.Items {
		if item.SoftwareName == "musl" {
			assert.Empty(t, item.Vendor)
			assert.Equal(t, "musl", item.SourcePackage)
			assert.Equal(t, item.Version, item.SourceVersion)
			assert.NotEmpty(t, item.Homepage)
			assert.Contains(t, item.Version, "-r")
			return
		}
	}
	t.Fatal("installed musl package missing")
}
