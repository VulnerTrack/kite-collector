package preflight

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntraTenantID_Empty(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(context.Background(), "discovery.sources.entra.tenant_id", "", nil)
	assert.True(t, r.Passed)
	assert.Contains(t, r.Message, "no tenant_id")
}

func TestEntraTenantID_Nil(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(context.Background(), "discovery.sources.entra.tenant_id", nil, nil)
	assert.True(t, r.Passed)
}

func TestEntraTenantID_ValidGUID(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.tenant_id",
		"72f988bf-86f1-41af-91ab-2d7cd011db47",
		nil,
	)
	assert.True(t, r.Passed, "got: %+v", r)
	assert.Contains(t, r.Message, "valid GUID")
}

func TestEntraTenantID_ValidGUIDBraced(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.tenant_id",
		"{72f988bf-86f1-41af-91ab-2d7cd011db47}",
		nil,
	)
	assert.True(t, r.Passed, "got: %+v", r)
}

func TestEntraTenantID_ValidGUIDUppercase(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.tenant_id",
		"72F988BF-86F1-41AF-91AB-2D7CD011DB47",
		nil,
	)
	assert.True(t, r.Passed, "got: %+v", r)
}

func TestEntraTenantID_NotGUID(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.tenant_id",
		"contoso.onmicrosoft.com",
		nil,
	)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "not a valid GUID")
	assert.Contains(t, r.Hint, "Directory (tenant) ID")
}

func TestEntraTenantID_TooShort(t *testing.T) {
	c := &EntraTenantIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.tenant_id",
		"72f988bf-86f1-41af-91ab",
		nil,
	)
	assert.False(t, r.Passed)
}

func TestEntraClientID_ValidGUID(t *testing.T) {
	c := &EntraClientIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.client_id",
		"a1b2c3d4-1234-5678-9abc-def012345678",
		nil,
	)
	assert.True(t, r.Passed, "got: %+v", r)
	assert.Contains(t, r.Message, "valid GUID")
}

func TestEntraClientID_Invalid(t *testing.T) {
	c := &EntraClientIDChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.client_id",
		"not-a-guid",
		nil,
	)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Hint, "Application (client) ID")
}

func TestEntraClientID_Empty(t *testing.T) {
	c := &EntraClientIDChecker{}
	r := c.Check(context.Background(), "discovery.sources.entra.client_id", "", nil)
	assert.True(t, r.Passed)
}

func TestEntraSecretEnv_VarSet(t *testing.T) {
	t.Setenv("KITE_ENTRA_CLIENT_SECRET_TEST", "s3cret")
	c := &EntraSecretEnvChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.client_secret_env",
		"KITE_ENTRA_CLIENT_SECRET_TEST",
		nil,
	)
	assert.True(t, r.Passed, "got: %+v", r)
	assert.Contains(t, r.Message, "is set")
}

func TestEntraSecretEnv_VarUnset(t *testing.T) {
	c := &EntraSecretEnvChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.client_secret_env",
		"KITE_ENTRA_CLIENT_SECRET_DEFINITELY_NOT_SET_42",
		nil,
	)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "is not set")
	assert.Contains(t, r.Hint, "export KITE_ENTRA_CLIENT_SECRET_DEFINITELY_NOT_SET_42")
}

func TestEntraSecretEnv_Empty(t *testing.T) {
	c := &EntraSecretEnvChecker{}
	r := c.Check(
		context.Background(),
		"discovery.sources.entra.client_secret_env",
		"",
		nil,
	)
	assert.True(t, r.Passed)
}

func TestEntraCheckers_RegisteredInRunner(t *testing.T) {
	r := NewRunner(2, slog.Default())
	specs := []CheckSpec{
		{
			NodeID:   "discovery.sources.entra.tenant_id",
			CheckTag: "entra:tenant_id:guid",
			Value:    "72f988bf-86f1-41af-91ab-2d7cd011db47",
		},
		{
			NodeID:   "discovery.sources.entra.client_id",
			CheckTag: "entra:client_id:guid",
			Value:    "a1b2c3d4-1234-5678-9abc-def012345678",
		},
		{
			NodeID:   "discovery.sources.entra.client_secret_env",
			CheckTag: "entra:secret:env",
			Value:    "",
		},
	}
	results := r.Run(context.Background(), specs)
	assert.Len(t, results, 3)
	for _, res := range results {
		assert.True(t, res.Passed, "expected pass for %s, got: %+v", res.Check, res)
	}
}
