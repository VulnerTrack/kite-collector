package classifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// ---------------------------------------------------------------------------
// Authorizer
// ---------------------------------------------------------------------------

func TestAuthorizer_NoEntries_ReturnsUnknown(t *testing.T) {
	auth, err := NewAuthorizer("", []string{"hostname"})
	require.NoError(t, err)

	asset := model.Asset{Hostname: "anything"}
	assert.Equal(t, model.AuthorizationUnknown, auth.Authorize(asset))
}

func TestAuthorizer_MatchingHostname_ReturnsAuthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}

	asset := model.Asset{Hostname: "web-01"}
	assert.Equal(t, model.AuthorizationAuthorized, auth.Authorize(asset))
}

func TestAuthorizer_NonMatchingHostname_ReturnsUnauthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}

	asset := model.Asset{Hostname: "rogue-box"}
	assert.Equal(t, model.AuthorizationUnauthorized, auth.Authorize(asset))
}

func TestAuthorizer_GlobPattern(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "server-*"}},
		matchFields: []string{"hostname"},
	}

	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Asset{Hostname: "server-01"}))
	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Asset{Hostname: "server-99"}))
	assert.Equal(t, model.AuthorizationUnauthorized,
		auth.Authorize(model.Asset{Hostname: "desktop-01"}))
}

func TestAuthorizer_CaseInsensitiveHostname(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "Web-01"}},
		matchFields: []string{"hostname"},
	}

	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Asset{Hostname: "web-01"}))
}

func TestAuthorizer_NoMatchFields_ReturnsUnauthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: nil,
	}

	// With entries but no match fields, entryMatches returns false for all
	assert.Equal(t, model.AuthorizationUnauthorized,
		auth.Authorize(model.Asset{Hostname: "web-01"}))
}

func TestAuthorizer_NonexistentFile_ReturnsUnknown(t *testing.T) {
	auth, err := NewAuthorizer("/tmp/nonexistent-kite-test-file.yaml", []string{"hostname"})
	require.NoError(t, err)

	// File not found results in zero entries, so "unknown"
	assert.Equal(t, model.AuthorizationUnknown,
		auth.Authorize(model.Asset{Hostname: "web-01"}))
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

func TestManager_EmptyControls_ReturnsUnknown(t *testing.T) {
	mgr := NewManager(nil)

	asset := model.Asset{Hostname: "host-01"}
	assert.Equal(t, model.ManagedUnknown, mgr.Evaluate(asset))
}

func TestManager_WithControls_ReturnsUnmanaged(t *testing.T) {
	mgr := NewManager([]string{"edr_agent", "config_mgmt"})

	asset := model.Asset{Hostname: "host-01"}
	assert.Equal(t, model.ManagedUnmanaged, mgr.Evaluate(asset))
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

func TestClassifier_ClassifyAll(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "known-*"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager([]string{"edr"})
	cls := New(auth, mgr)

	assets := []model.Asset{
		{Hostname: "known-01", AssetType: model.AssetTypeServer},
		{Hostname: "rogue-01", AssetType: model.AssetTypeWorkstation},
	}

	result := cls.ClassifyAll(assets)
	require.Len(t, result, 2)

	assert.Equal(t, model.AuthorizationAuthorized, result[0].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[0].IsManaged)

	assert.Equal(t, model.AuthorizationUnauthorized, result[1].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[1].IsManaged)
}

func TestClassifier_ClassifySingle(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager(nil)
	cls := New(auth, mgr)

	asset := model.Asset{Hostname: "web-01"}
	cls.Classify(&asset)

	assert.Equal(t, model.AuthorizationAuthorized, asset.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, asset.IsManaged)
}
