package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVersionPinned guards against accidentally bumping the Version constant
// without updating the JSON Schema in lock-step. The schema's `version`
// const must equal the Go constant.
func TestVersionPinned(t *testing.T) {
	schema := loadSchema(t)
	props := schema["properties"].(map[string]any)
	v := props["version"].(map[string]any)
	assert.Equal(t, Version, v["const"], "v1.json version const must match Go contract.Version")
}

// TestGoldenResource validates the resource fixture against
// RequiredResourceAttributes and AllowedResourceAttributes.
func TestGoldenResource(t *testing.T) {
	res := loadGolden(t, "resource.json")

	for _, k := range RequiredResourceAttributes {
		_, ok := res[string(k)]
		assert.Truef(t, ok, "resource fixture missing required key %q", k)
	}
	for k := range res {
		assert.Truef(t, IsAllowedResourceAttribute(k),
			"resource fixture contains key not in allow-set: %q", k)
	}

	assert.Equal(t, ServiceName, res[string(ResAttrServiceName)])
	assert.Equal(t, ServiceNamespace, res[string(ResAttrServiceNamespace)])
	assert.Equal(t, AgentType, res[string(ResAttrAgentType)])
	assert.Equal(t, Version, res[string(ResAttrContractVersion)])
}

// TestGoldenEvents validates one fixture per declared EventName.
func TestGoldenEvents(t *testing.T) {
	cases := []struct {
		file  string
		event EventName
	}{
		{"log_asset_discovered.json", EventAssetDiscovered},
		{"log_asset_changed.json", EventAssetChanged},
		{"log_finding_configuration.json", EventFindingConfiguration},
		{"log_finding_posture.json", EventFindingPosture},
		{"log_scan_lifecycle.json", EventScanLifecycle},
	}
	for _, c := range cases {
		t.Run(string(c.event), func(t *testing.T) {
			fx := loadGoldenAny(t, c.file)

			// event.domain must be the constant.
			assert.Equal(t, EventDomain, fx[AttrEventDomain],
				"event.domain must be %q", EventDomain)

			// event.name must equal the declared name.
			assert.Equal(t, string(c.event), fx[AttrEventName],
				"event.name must equal the declared name")

			// All keys must be allowed for this event.
			for k := range fx {
				assert.Truef(t, IsAllowedEventAttribute(c.event, k),
					"event %s: key %q not declared in EventAttributes", c.event, k)
			}

			// All required keys present.
			for _, k := range EventRequiredAttributes[c.event] {
				_, ok := fx[k]
				assert.Truef(t, ok, "event %s: missing required key %q", c.event, k)
			}
		})
	}
}

// TestSeverityToIDMapping pins the severity → severity_id contract.
func TestSeverityToIDMapping(t *testing.T) {
	for sev := range AllowedSeverities {
		id, ok := SeverityToID[sev]
		assert.Truef(t, ok, "severity %q has no severity_id mapping", sev)
		assert.GreaterOrEqual(t, id, 1)
		assert.LessOrEqual(t, id, 5)
	}
}

// TestPredicates covers the closed-set predicates with both allow and reject
// cases so the IsAllowed* helpers stay trustworthy even when a future change
// extends one of the underlying maps.
func TestPredicates(t *testing.T) {
	t.Run("event_name", func(t *testing.T) {
		for n := range AllowedEventNames {
			assert.Truef(t, IsAllowedEventName(string(n)), "expected %q allowed", n)
		}
		for _, n := range []string{"", "kite.asset.discovered", "asset.unknown", "scan", "Asset.Discovered"} {
			assert.Falsef(t, IsAllowedEventName(n), "expected %q rejected", n)
		}
	})
	t.Run("event_attribute", func(t *testing.T) {
		assert.True(t, IsAllowedEventAttribute(EventAssetDiscovered, "security.asset.uid"))
		assert.False(t, IsAllowedEventAttribute(EventAssetDiscovered, "security.finding.uid"),
			"finding key must not be allowed on asset.discovered")
		assert.False(t, IsAllowedEventAttribute(EventName("nope"), AttrEventDomain),
			"unknown event short-circuits to false")
	})
	t.Run("metric", func(t *testing.T) {
		for name := range Metrics {
			assert.Truef(t, IsAllowedMetric(name), "expected %q allowed", name)
		}
		for _, n := range []string{"", "kite.unknown", "scan.duration"} {
			assert.Falsef(t, IsAllowedMetric(n), "expected %q rejected", n)
		}
	})
	t.Run("resource_attribute", func(t *testing.T) {
		for k := range AllowedResourceAttributes {
			assert.Truef(t, IsAllowedResourceAttribute(string(k)), "expected %q allowed", k)
		}
		for _, k := range []string{"", "service", "host", "kite.contract"} {
			assert.Falsef(t, IsAllowedResourceAttribute(k), "expected %q rejected", k)
		}
	})
}

// TestSpanNameMatcher covers the dynamic discover.<source> and audit.<module>
// expansion in IsAllowedSpanName.
func TestSpanNameMatcher(t *testing.T) {
	good := []string{
		"scan", "discover", "dedup", "classify", "audit",
		"posture", "policy", "persist", "emit",
		"discover.docker", "discover.cloud.aws", "discover.vpn.tailscale",
		"audit.ssh", "audit.firewall",
	}
	for _, n := range good {
		assert.Truef(t, IsAllowedSpanName(n), "expected %q to be allowed", n)
	}

	bad := []string{
		"", "Scan", "discovery", "discover.unknown",
		"audit.kernel", "discover.", "audit.",
	}
	for _, n := range bad {
		assert.Falsef(t, IsAllowedSpanName(n), "expected %q to be rejected", n)
	}
}

// TestMetricCatalogShape pins the metric catalog: every entry has a name,
// kind, and unit; labels (when present) are non-empty strings.
func TestMetricCatalogShape(t *testing.T) {
	for name, m := range Metrics {
		assert.Equal(t, name, m.Name, "metric map key must equal definition.Name")
		assert.NotEmpty(t, m.Unit, "%s: unit must not be empty", name)
		switch m.Kind {
		case MetricKindCounter, MetricKindUpDownCounter, MetricKindHistogram:
		default:
			t.Fatalf("%s: unknown kind %q", name, m.Kind)
		}
		for _, l := range m.Labels {
			assert.NotEmpty(t, l, "%s: empty label", name)
		}
	}
}

// TestCardinalityBudgetReferencesContractKeys ensures each budgeted key is
// either an allowed event attribute, an enum dimension, or AttrEventName.
func TestCardinalityBudgetReferencesContractKeys(t *testing.T) {
	known := map[string]struct{}{
		"discovery.source": {}, "audit.module": {},
	}
	// Walk the union of every event's allowed attribute keys.
	for _, attrs := range EventAttributes {
		for k := range attrs {
			known[k] = struct{}{}
		}
	}
	for k := range CardinalityBudget {
		_, ok := known[k]
		assert.Truef(t, ok, "cardinality budget references unknown key %q", k)
	}
}

// loadSchema parses v1.json from the package directory.
func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("v1.json")
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// loadGolden reads a string-valued JSON fixture.
func loadGolden(t *testing.T, name string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("golden", name))
	require.NoError(t, err)
	var out map[string]string
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// loadGoldenAny reads a fixture that may contain non-string values
// (severity_id, duration_ms).
func loadGoldenAny(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("golden", name))
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}
