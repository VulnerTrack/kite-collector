package software

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run only in a disposable Debian/Ubuntu container with perl and git installed.
func TestCPANInstalledOwnershipIntegration(t *testing.T) {
	if os.Getenv("KITE_TEST_NATIVE_CPAN") != "1" {
		t.Skip("requires disposable Debian/Ubuntu container with perl and git")
	}
	result, err := NewCPAN().Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, result.Items)
	owned := 0
	sources := map[string]int{}
	for _, item := range result.Items {
		if item.PackageOwner != nil {
			owned++
			sources[item.PackageOwner.SourcePackage]++
		}
	}
	t.Logf("module rows=%d, native owner=%d, unresolved owner=%d, source packages=%v",
		len(result.Items), owned, len(result.Items)-owned, sources)
	for module, source := range map[string]string{"File::Spec::Unix": "perl", "Git::I18N": "git"} {
		found := false
		for _, item := range result.Items {
			if item.SoftwareName != module {
				continue
			}
			found = true
			require.NotNilf(t, item.PackageOwner, "native owner missing for %s", module)
			assert.Equal(t, source, item.PackageOwner.SourcePackage)
			assert.NotEmpty(t, item.PackageOwner.SourceVersion)
			assert.Equal(t, item.InstallPath, item.PackageOwner.File)
			assert.Equal(t, "cpan", item.PackageManager)
			evidence, err := json.Marshal(item)
			require.NoError(t, err)
			t.Logf("ownership_evidence=%s", evidence)
		}
		assert.Truef(t, found, "%s missing from CPAN inventory", module)
	}
}
