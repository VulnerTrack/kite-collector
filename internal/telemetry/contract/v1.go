// Package contract is the machine-checkable agent → central OTel telemetry
// contract defined in RFC-0115. It declares the closed sets of resource
// attributes, log event names, span names, metric instruments, and per-event
// attribute keys that the kite-collector agent is permitted to emit.
//
// The Go declarations in this file are the authoritative source. The sibling
// v1.json document mirrors them in JSON Schema 2020-12 form for downstream
// consumers (the OTel Collector, Grafana, the ontology bridge).
//
// Adding a new attribute, event, span, or metric requires editing both files
// in the same change so contract_test.go stays green.
package contract

// Version is the contract version this build was compiled against.
//
// SemVer rules per RFC-0115 §4.9:
//   - patch/minor bumps are additive (new MAY attributes, new MAY span
//     attributes, new metric labels, closed enums extended)
//   - major bumps remove or rename a MUST attribute, change an enum's
//     semantics, or remove an event — they require a 90-day dual-emit
//     window per RFC-0115 §2.3.
const Version = "1.0"

// ResourceAttributeKey enumerates every resource attribute the agent is
// permitted to attach to a signal. The set is closed: anything not declared
// here will be flagged by the contract validator and dropped at the
// Collector's filter/contract processor.
type ResourceAttributeKey string

const (
	ResAttrServiceName       ResourceAttributeKey = "service.name"
	ResAttrServiceVersion    ResourceAttributeKey = "service.version"
	ResAttrServiceNamespace  ResourceAttributeKey = "service.namespace"
	ResAttrServiceInstanceID ResourceAttributeKey = "service.instance.id"
	ResAttrHostID            ResourceAttributeKey = "host.id"
	ResAttrHostName          ResourceAttributeKey = "host.name"
	ResAttrHostArch          ResourceAttributeKey = "host.arch"
	ResAttrOSType            ResourceAttributeKey = "os.type"
	ResAttrOSName            ResourceAttributeKey = "os.name"
	ResAttrOSVersion         ResourceAttributeKey = "os.version"
	ResAttrAgentID           ResourceAttributeKey = "agent.id"
	ResAttrAgentType         ResourceAttributeKey = "agent.type"
	ResAttrTenantID          ResourceAttributeKey = "tenant.id"
	ResAttrDeploymentEnv     ResourceAttributeKey = "deployment.environment"
	ResAttrContractVersion   ResourceAttributeKey = "kite.contract.version"
)

// RequiredResourceAttributes lists keys that MUST appear on every signal.
// Per RFC-0115 §4.2 every key is currently required; the slice is provided
// so future minor versions can introduce optional keys without restating
// this list.
var RequiredResourceAttributes = []ResourceAttributeKey{
	ResAttrServiceName,
	ResAttrServiceVersion,
	ResAttrServiceNamespace,
	ResAttrServiceInstanceID,
	ResAttrHostID,
	ResAttrHostName,
	ResAttrHostArch,
	ResAttrOSType,
	ResAttrOSName,
	ResAttrOSVersion,
	ResAttrAgentID,
	ResAttrAgentType,
	ResAttrTenantID,
	ResAttrDeploymentEnv,
	ResAttrContractVersion,
}

// AllowedResourceAttributes is the closed set of resource keys.
var AllowedResourceAttributes = map[ResourceAttributeKey]struct{}{
	ResAttrServiceName:       {},
	ResAttrServiceVersion:    {},
	ResAttrServiceNamespace:  {},
	ResAttrServiceInstanceID: {},
	ResAttrHostID:            {},
	ResAttrHostName:          {},
	ResAttrHostArch:          {},
	ResAttrOSType:            {},
	ResAttrOSName:            {},
	ResAttrOSVersion:         {},
	ResAttrAgentID:           {},
	ResAttrAgentType:         {},
	ResAttrTenantID:          {},
	ResAttrDeploymentEnv:     {},
	ResAttrContractVersion:   {},
}

// Constant values for resource attributes whose value is fixed by the contract.
const (
	ServiceName      = "kite-collector"
	ServiceNamespace = "vulnertrack"
	AgentType        = "kite-collector"
)

// EventName enumerates the closed set of log-record event names per
// RFC-0115 §4.4. Records carrying any other event.name are dropped at the
// Collector.
type EventName string

const (
	EventAssetDiscovered      EventName = "asset.discovered"
	EventAssetChanged         EventName = "asset.changed"
	EventFindingConfiguration EventName = "finding.configuration"
	EventFindingPosture       EventName = "finding.posture"
	EventScanLifecycle        EventName = "scan.lifecycle"
)

// AllowedEventNames is the closed event-name set.
var AllowedEventNames = map[EventName]struct{}{
	EventAssetDiscovered:      {},
	EventAssetChanged:         {},
	EventFindingConfiguration: {},
	EventFindingPosture:       {},
	EventScanLifecycle:        {},
}

// EventDomain is the constant domain prefix every record carries.
const EventDomain = "security"

// Common attribute keys shared across multiple events.
const (
	AttrEventDomain = "event.domain"
	AttrEventName   = "event.name"
	AttrScanUID     = "security.scan.uid"
)

// Span names per RFC-0115 §4.5. Names with a "<source>" or "<module>" suffix
// expand into the per-source and per-module forms enumerated by
// AllowedDiscoverySources and AllowedAuditModules.
const (
	SpanScan        = "scan"
	SpanDiscover    = "discover"
	SpanDiscoverPfx = "discover."
	SpanDedup       = "dedup"
	SpanClassify    = "classify"
	SpanAudit       = "audit"
	SpanAuditPfx    = "audit."
	SpanPosture     = "posture"
	SpanPolicy      = "policy"
	SpanPersist     = "persist"
	SpanEmit        = "emit"
)

// AllowedDiscoverySources is the closed enum used both as the
// security.asset.discovery.source attribute (§4.4.1) and as the
// discover.<source> span suffix (§4.5).
var AllowedDiscoverySources = map[string]struct{}{
	"agent":           {},
	"arp":             {},
	"icmp":            {},
	"tcp_syn":         {},
	"docker":          {},
	"cloud.aws":       {},
	"cloud.gcp":       {},
	"cloud.azure":     {},
	"vpn.tailscale":   {},
	"vpn.netbird":     {},
	"dns":             {},
	"ssh-known-hosts": {},
}

// AllowedAuditModules is the closed audit.<module> span suffix.
var AllowedAuditModules = map[string]struct{}{
	"ssh":         {},
	"firewall":    {},
	"permissions": {},
	"tls":         {},
}

// AllowedAssetTypes per §4.4.1.
var AllowedAssetTypes = map[string]struct{}{
	"server":         {},
	"workstation":    {},
	"container":      {},
	"vm":             {},
	"network-device": {},
	"iot":            {},
	"unknown":        {},
}

// AllowedAuthorization per §4.4.1.
var AllowedAuthorization = map[string]struct{}{
	"authorized":   {},
	"unauthorized": {},
	"unknown":      {},
}

// AllowedManagedStatus per §4.4.1.
var AllowedManagedStatus = map[string]struct{}{
	"managed":   {},
	"unmanaged": {},
	"unknown":   {},
}

// AllowedFindingTypes per §4.4.3.
var AllowedFindingTypes = map[string]struct{}{
	"misconfiguration": {},
	"weak-cipher":      {},
	"unpatched":        {},
	"permission":       {},
	"policy":           {},
}

// AllowedSeverities per §4.4.3 / §4.4.4.
var AllowedSeverities = map[string]struct{}{
	"info":     {},
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// AllowedScanPhases per §4.4.5.
var AllowedScanPhases = map[string]struct{}{
	"started":   {},
	"completed": {},
	"failed":    {},
	"cancelled": {},
}

// AllowedScanErrorKinds per §4.4.5.
var AllowedScanErrorKinds = map[string]struct{}{
	"network":    {},
	"permission": {},
	"timeout":    {},
	"internal":   {},
	"none":       {},
}

// AllowedFindingLikelihoods per §4.4.4.
var AllowedFindingLikelihoods = map[string]struct{}{
	"low":    {},
	"medium": {},
	"high":   {},
}

// EventAttributes maps each EventName to the set of attribute keys that
// records of that event are allowed to carry. Records may include any subset
// of the listed keys; required-vs-optional is enforced separately by
// EventRequiredAttributes.
var EventAttributes = map[EventName]map[string]struct{}{
	EventAssetDiscovered: {
		AttrEventDomain:                   {},
		AttrEventName:                     {},
		AttrScanUID:                       {},
		"security.asset.uid":              {},
		"security.asset.type":             {},
		"security.asset.name":             {},
		"security.asset.os.name":          {},
		"security.asset.os.version":       {},
		"security.asset.ip.v4":            {},
		"security.asset.ip.v6":            {},
		"security.asset.mac":              {},
		"security.asset.fqdn":             {},
		"security.asset.authorization":    {},
		"security.asset.managed_status":   {},
		"security.asset.first_seen":       {},
		"security.asset.discovery.source": {},
	},
	EventAssetChanged: {
		AttrEventDomain:                   {},
		AttrEventName:                     {},
		AttrScanUID:                       {},
		"security.asset.uid":              {},
		"security.asset.type":             {},
		"security.asset.name":             {},
		"security.asset.os.name":          {},
		"security.asset.os.version":       {},
		"security.asset.ip.v4":            {},
		"security.asset.ip.v6":            {},
		"security.asset.mac":              {},
		"security.asset.fqdn":             {},
		"security.asset.authorization":    {},
		"security.asset.managed_status":   {},
		"security.asset.first_seen":       {},
		"security.asset.discovery.source": {},
		"security.asset.change.field":     {},
		"security.asset.change.before":    {},
		"security.asset.change.after":     {},
	},
	EventFindingConfiguration: {
		AttrEventDomain:                     {},
		AttrEventName:                       {},
		AttrScanUID:                         {},
		"security.finding.uid":              {},
		"security.finding.type":             {},
		"security.finding.title":            {},
		"security.finding.severity":         {},
		"security.finding.severity_id":      {},
		"security.finding.cwe.uid":          {},
		"security.finding.cwe.name":         {},
		"security.finding.capec.uid":        {},
		"security.finding.cis_control":      {},
		"security.finding.remediation.desc": {},
		"security.finding.evidence":         {},
		"security.finding.expected":         {},
		"security.asset.uid":                {},
		"security.asset.name":               {},
	},
	EventFindingPosture: {
		AttrEventDomain:                     {},
		AttrEventName:                       {},
		AttrScanUID:                         {},
		"security.finding.uid":              {},
		"security.finding.type":             {},
		"security.finding.title":            {},
		"security.finding.severity":         {},
		"security.finding.severity_id":      {},
		"security.finding.cwe.uid":          {},
		"security.finding.cwe.name":         {},
		"security.finding.capec.uid":        {},
		"security.finding.cis_control":      {},
		"security.finding.remediation.desc": {},
		"security.finding.likelihood":       {},
		"security.finding.mitigation":       {},
		"security.asset.uid":                {},
		"security.asset.name":               {},
	},
	EventScanLifecycle: {
		AttrEventDomain:             {},
		AttrEventName:               {},
		AttrScanUID:                 {},
		"security.scan.phase":       {},
		"security.scan.duration_ms": {},
		"security.scan.error.kind":  {},
	},
}

// EventRequiredAttributes lists the MUST-have keys for each event per
// §4.4.1–4.4.5. Missing keys cause the contract validator to fail.
var EventRequiredAttributes = map[EventName][]string{
	EventAssetDiscovered: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.asset.uid",
		"security.asset.type",
		"security.asset.name",
		"security.asset.authorization",
		"security.asset.managed_status",
		"security.asset.first_seen",
		"security.asset.discovery.source",
	},
	EventAssetChanged: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.asset.uid",
		"security.asset.type",
		"security.asset.name",
		"security.asset.authorization",
		"security.asset.managed_status",
		"security.asset.change.field",
	},
	EventFindingConfiguration: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.finding.uid",
		"security.finding.type",
		"security.finding.title",
		"security.finding.severity",
		"security.finding.severity_id",
		"security.asset.uid",
		"security.asset.name",
	},
	EventFindingPosture: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.finding.uid",
		"security.finding.type",
		"security.finding.title",
		"security.finding.severity",
		"security.finding.severity_id",
		"security.finding.likelihood",
		"security.asset.uid",
		"security.asset.name",
	},
	EventScanLifecycle: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.scan.phase",
	},
}

// SeverityToID is the canonical severity → severity_id mapping per §4.4.3.
var SeverityToID = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// MetricKind enumerates the OTel instrument kinds the contract permits.
type MetricKind string

const (
	MetricKindCounter       MetricKind = "counter"
	MetricKindUpDownCounter MetricKind = "up_down_counter"
	MetricKindHistogram     MetricKind = "histogram"
)

// MetricDefinition pins a metric instrument's name, kind, unit, and label
// keys to the values declared in RFC-0115 §4.6.
type MetricDefinition struct {
	Name   string
	Kind   MetricKind
	Unit   string
	Labels []string
}

// Metrics is the closed instrument catalog. The Collector drops any
// instrument not in this list.
var Metrics = map[string]MetricDefinition{
	"kite.scan.duration": {
		Name: "kite.scan.duration", Kind: MetricKindHistogram, Unit: "s",
		Labels: []string{"scan.type", "status"},
	},
	"kite.scan.runs.count": {
		Name: "kite.scan.runs.count", Kind: MetricKindCounter, Unit: "{scan}",
		Labels: []string{"scan.type", "status"},
	},
	"kite.discovery.duration": {
		Name: "kite.discovery.duration", Kind: MetricKindHistogram, Unit: "s",
		Labels: []string{"discovery.source"},
	},
	"kite.discovery.assets.found": {
		Name: "kite.discovery.assets.found", Kind: MetricKindCounter, Unit: "{asset}",
		Labels: []string{"discovery.source"},
	},
	"kite.discovery.errors.count": {
		Name: "kite.discovery.errors.count", Kind: MetricKindCounter, Unit: "{error}",
		Labels: []string{"discovery.source", "error.kind"},
	},
	"kite.assets.total": {
		Name: "kite.assets.total", Kind: MetricKindUpDownCounter, Unit: "{asset}",
		Labels: []string{"asset.type", "authorization"},
	},
	"kite.assets.stale": {
		Name: "kite.assets.stale", Kind: MetricKindUpDownCounter, Unit: "{asset}",
	},
	"kite.findings.count": {
		Name: "kite.findings.count", Kind: MetricKindCounter, Unit: "{finding}",
		Labels: []string{"finding.type", "severity"},
	},
	"kite.findings.open": {
		Name: "kite.findings.open", Kind: MetricKindUpDownCounter, Unit: "{finding}",
		Labels: []string{"severity"},
	},
	"kite.events.emitted.count": {
		Name: "kite.events.emitted.count", Kind: MetricKindCounter, Unit: "{event}",
		Labels: []string{"event.name"},
	},
	"kite.otlp.export.duration": {
		Name: "kite.otlp.export.duration", Kind: MetricKindHistogram, Unit: "s",
		Labels: []string{"signal", "status"},
	},
	"kite.otlp.export.bytes": {
		Name: "kite.otlp.export.bytes", Kind: MetricKindCounter, Unit: "By",
		Labels: []string{"signal"},
	},
	"kite.otlp.queue.size": {
		Name: "kite.otlp.queue.size", Kind: MetricKindUpDownCounter, Unit: "{record}",
		Labels: []string{"signal"},
	},
	"kite.otlp.dropped.count": {
		Name: "kite.otlp.dropped.count", Kind: MetricKindCounter, Unit: "{record}",
		Labels: []string{"signal", "reason"},
	},
}

// AllowedSignals is the closed set of values for the metric `signal` label
// and the otlp.* metric `signal` dimension.
var AllowedSignals = map[string]struct{}{
	"logs":    {},
	"traces":  {},
	"metrics": {},
}

// CardinalityBudget records the per-tenant per-day distinct-value budget for
// each declared attribute key per RFC-0115 §4.8. Zero means unbounded /
// unset; the Collector enforces non-zero values.
var CardinalityBudget = map[string]int{
	"security.finding.cwe.uid":   1500,
	"security.finding.capec.uid": 600,
	"security.asset.uid":         1_000_000,
	"security.asset.fqdn":        200_000,
	"security.scan.uid":          100_000,
	"discovery.source":           16,
	"audit.module":               16,
	AttrEventName:                5,
}

// IsAllowedResourceAttribute reports whether key is in the closed resource
// attribute set.
func IsAllowedResourceAttribute(key string) bool {
	_, ok := AllowedResourceAttributes[ResourceAttributeKey(key)]
	return ok
}

// IsAllowedEventName reports whether name is in the closed event name set.
func IsAllowedEventName(name string) bool {
	_, ok := AllowedEventNames[EventName(name)]
	return ok
}

// IsAllowedEventAttribute reports whether key is permitted on a record with
// the given event name.
func IsAllowedEventAttribute(event EventName, key string) bool {
	allowed, ok := EventAttributes[event]
	if !ok {
		return false
	}
	_, found := allowed[key]
	return found
}

// IsAllowedSpanName reports whether name matches one of the declared spans,
// including the dynamic discover.<source> and audit.<module> forms.
func IsAllowedSpanName(name string) bool {
	switch name {
	case SpanScan, SpanDiscover, SpanDedup, SpanClassify,
		SpanAudit, SpanPosture, SpanPolicy, SpanPersist, SpanEmit:
		return true
	}
	if len(name) > len(SpanDiscoverPfx) && name[:len(SpanDiscoverPfx)] == SpanDiscoverPfx {
		_, ok := AllowedDiscoverySources[name[len(SpanDiscoverPfx):]]
		return ok
	}
	if len(name) > len(SpanAuditPfx) && name[:len(SpanAuditPfx)] == SpanAuditPfx {
		_, ok := AllowedAuditModules[name[len(SpanAuditPfx):]]
		return ok
	}
	return false
}

// IsAllowedMetric reports whether the named metric instrument is in the
// catalog.
func IsAllowedMetric(name string) bool {
	_, ok := Metrics[name]
	return ok
}
