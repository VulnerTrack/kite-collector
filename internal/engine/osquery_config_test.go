package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	osquerydisc "github.com/vulnertrack/kite-collector/internal/discovery/osquery"
)

// The osquery source documents socket/yara_* as its config keys, but a key the
// source reads and buildSourceConfigMap never writes is unreachable from the
// YAML file: the socket would resolve by env var or platform probe only, and a
// YARA sweep could not be armed at all.
func TestBuildSourceConfigMap_CarriesTheOsqueryKeys(t *testing.T) {
	m := buildSourceConfigMap("osquery", config.SourceConfig{
		Socket:      "/var/kite-osquery/kite-osquery.em",
		YaraSigfile: "/etc/osquery/yara/kite.yar",
		YaraRules:   "rule r { condition: true }",
		YaraPaths:   []string{"/usr/local/bin/*", "/Applications/*"},
	})

	assert.Equal(t, "/var/kite-osquery/kite-osquery.em", m["socket"])
	assert.Equal(t, "/etc/osquery/yara/kite.yar", m["yara_sigfile"])
	assert.Equal(t, "rule r { condition: true }", m["yara_rules"])
	assert.Equal(t, []any{"/usr/local/bin/*", "/Applications/*"}, m["yara_paths"])
}

// The socket precedence is cfg -> env -> probe. Proving it end to end through
// the map the engine actually builds is what stops the two halves drifting.
func TestOsqueryConfigMapDrivesSocketResolution(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/tmp/env-wins-over-probe.em")

	fromYAML := buildSourceConfigMap("osquery", config.SourceConfig{
		Socket: "/tmp/yaml-wins.em",
	})
	require.Equal(t, "/tmp/yaml-wins.em", osquerydisc.ResolveSocket(fromYAML))

	noSocket := buildSourceConfigMap("osquery", config.SourceConfig{})
	assert.Equal(t, "/tmp/env-wins-over-probe.em", osquerydisc.ResolveSocket(noSocket),
		"an empty socket key must fall through to the env var, not pin an empty path")
}

// yara_paths must stay distinct from the shared `paths` field: other sources
// use `paths` for something else entirely, and folding the two would arm a
// YARA sweep over whatever they configured.
func TestOsqueryYaraPathsAreNotTheSharedPathsField(t *testing.T) {
	m := buildSourceConfigMap("osquery", config.SourceConfig{
		Paths:     []string{"/not/a/yara/target"},
		YaraPaths: []string{"/usr/local/bin/*"},
	})
	assert.NotEqual(t, m["paths"], m["yara_paths"])
	assert.Equal(t, []any{"/usr/local/bin/*"}, m["yara_paths"])
}
