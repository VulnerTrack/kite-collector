package resource

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

func TestBuild_PopulatesEveryRequiredKey(t *testing.T) {
	cfg := Config{
		AgentID:        uuid.Must(uuid.NewV7()),
		ServiceVersion: "1.2.3",
		TenantID:       "acme",
		Environment:    "pilot",
	}
	got := Build(cfg)

	for _, k := range contract.RequiredResourceAttributes {
		v, ok := got[string(k)]
		assert.Truef(t, ok, "missing required resource attribute %q", k)
		assert.NotEmptyf(t, v, "empty value for %q", k)
	}
}

func TestBuild_ConstantValuesMatchContract(t *testing.T) {
	got := Build(Config{
		AgentID:        uuid.Must(uuid.NewV7()),
		ServiceVersion: "9.9.9",
	})
	assert.Equal(t, contract.ServiceName, got[string(contract.ResAttrServiceName)])
	assert.Equal(t, contract.ServiceNamespace, got[string(contract.ResAttrServiceNamespace)])
	assert.Equal(t, contract.AgentType, got[string(contract.ResAttrAgentType)])
	assert.Equal(t, contract.Version, got[string(contract.ResAttrContractVersion)])
	assert.Equal(t, "9.9.9", got[string(contract.ResAttrServiceVersion)])
}

func TestBuild_UsesAgentIDForBothInstanceAndAgent(t *testing.T) {
	id := uuid.Must(uuid.NewV7())
	got := Build(Config{AgentID: id, ServiceVersion: "x"})
	assert.Equal(t, id.String(), got[string(contract.ResAttrServiceInstanceID)])
	assert.Equal(t, id.String(), got[string(contract.ResAttrAgentID)])
}

func TestBuild_DefaultsForOptionalConfig(t *testing.T) {
	got := Build(Config{
		AgentID:        uuid.Must(uuid.NewV7()),
		ServiceVersion: "1",
	})
	assert.Equal(t, "production", got[string(contract.ResAttrDeploymentEnv)])
	assert.Equal(t, "unknown", got[string(contract.ResAttrTenantID)])
}

func TestBuild_OnlyContractKeys(t *testing.T) {
	got := Build(Config{
		AgentID:        uuid.Must(uuid.NewV7()),
		ServiceVersion: "1",
	})
	for k := range got {
		assert.Truef(t, contract.IsAllowedResourceAttribute(k),
			"resource emitted disallowed key %q", k)
	}
}

func TestSplitOSReleaseLine(t *testing.T) {
	cases := map[string][2]string{
		`ID=ubuntu`:            {"ID", "ubuntu"},
		`VERSION_ID="22.04"`:   {"VERSION_ID", "22.04"},
		`PRETTY_NAME='Alpine'`: {"PRETTY_NAME", "Alpine"},
		``:                     {"", ""},
		`# comment`:            {"", ""},
	}
	for line, want := range cases {
		k, v := splitOSReleaseLine(line)
		assert.Equal(t, want[0], k, line)
		assert.Equal(t, want[1], v, line)
	}
}
