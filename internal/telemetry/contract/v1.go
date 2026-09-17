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
//
// 1.1 (additive): adds EventProbeHeartbeat for synthetic per-source liveness
// signals plus tamper detection. No prior attribute removed or renamed.
const Version = "1.3"

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
	EventMachineDiscovered    EventName = "machine.discovered"
	EventMachineChanged       EventName = "machine.changed"
	EventFindingConfiguration EventName = "finding.configuration"
	EventFindingPosture       EventName = "finding.posture"
	EventScanLifecycle        EventName = "scan.lifecycle"
	// EventProbeHeartbeat is a synthetic per-source liveness record. Every
	// discovery source emits one per scan whether or not it found anything,
	// so the absence of a heartbeat is itself an alert-grade signal (silent
	// collector failure, AV quarantine, wedged probe). Carries an Ed25519
	// signature plus the running binary's SHA-256 so the reconciler can
	// detect tampering.
	EventProbeHeartbeat EventName = "probe.heartbeat"
)

// AllowedEventNames is the closed event-name set.
var AllowedEventNames = map[EventName]struct{}{
	EventMachineDiscovered:    {},
	EventMachineChanged:       {},
	EventFindingConfiguration: {},
	EventFindingPosture:       {},
	EventScanLifecycle:        {},
	EventProbeHeartbeat:       {},
}

// EventDomain is the constant domain prefix every record carries.
const EventDomain = "security"

// Common attribute keys shared across multiple events.
const (
	AttrEventDomain = "event.domain"
	AttrEventName   = "event.name"
	AttrScanUID     = "security.scan.uid"
)

// Per-record signature attribute keys (v1.3, additive). Every log record
// carries all three: an Ed25519 signature over the record's canonical form,
// the "sha256:<hex>" fingerprint of the agent public key that produced it,
// and the algorithm name. The canonical form and the verifier live in
// internal/telemetry/recordsig; the values here must stay equal to that
// package's constants (pinned by a test in internal/emitter).
const (
	AttrRecordSignature         = "kite.record.signature"
	AttrRecordSignerFingerprint = "kite.record.signer.fingerprint"
	AttrRecordSignatureAlg      = "kite.record.signature.alg"
)

// recordSignatureAttributes is folded into every event's allow-set.
var recordSignatureAttributes = map[string]struct{}{
	AttrRecordSignature:         {},
	AttrRecordSignerFingerprint: {},
	AttrRecordSignatureAlg:      {},
}

// Probe heartbeat attribute keys (§ EventProbeHeartbeat).
const (
	AttrProbeSource       = "kite.probe.source"
	AttrProbeStatus       = "kite.probe.status"
	AttrProbeItemsEmitted = "kite.probe.items_emitted"
	AttrProbeDurationMs   = "kite.probe.duration_ms"
	AttrProbeBinaryHash   = "kite.probe.binary_hash"
	AttrProbeSignature    = "kite.probe.signature"
)

// AllowedProbeStatus is the closed enum for the kite.probe.status attribute.
var AllowedProbeStatus = map[string]struct{}{
	"ok":           {},
	"error":        {},
	"timeout":      {},
	"circuit_open": {},
}

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
// security.machine.discovery.source attribute (§4.4.1) and as the
// discover.<source> span suffix (§4.5).
var AllowedDiscoverySources = map[string]struct{}{
	"agent":       {},
	"arp":         {},
	"icmp":        {},
	"tcp_syn":     {},
	"docker":      {},
	"cloud.aws":   {},
	"cloud.gcp":   {},
	"cloud.azure": {},
	// VPN host-discovery source (internal/discovery/vpn): one label per
	// fabric, emitted as the discovery_source suffix on peers it enumerates.
	"vpn.tailscale":        {},
	"vpn.netbird":          {},
	"vpn.wireguard":        {},
	"vpn.zerotier":         {},
	"vpn.ipsec":            {},
	"vpn.openvpn":          {},
	"vpn.nebula":           {},
	"vpn.cisco-anyconnect": {},
	"vpn.mullvad":          {},
	"vpn.globalprotect":    {},
	"dns":                  {},
	"ssh-known-hosts":      {},
	"ldap":                 {},
}

// LDAP/Active Directory machine tag keys per RFC-0121 §5.4. These keys are
// emitted on EventMachineDiscovered records produced by the LDAP discovery
// source and consumed by the Python ontology bridge to materialize
// ActiveDirectoryDomain / ActiveDirectoryAccount / OrganizationalUnit
// entities. Values are JSON-encoded for collection-typed fields (spns,
// groups) so they round-trip through the OTLP string attribute layer.
const (
	AttrADDomainDNSName      = "ad.domain_dns_name"
	AttrADSAMAccountName     = "ad.sam_account_name"
	AttrADObjectSID          = "ad.object_sid"
	AttrADOUPath             = "ad.ou_path"
	AttrADEnabled            = "ad.enabled"
	AttrADLastLogonTimestamp = "ad.last_logon_timestamp"
	AttrADPasswordLastSet    = "ad.password_last_set"
	AttrADSPNs               = "ad.spns"
	AttrADGroups             = "ad.groups"
	AttrADUACFlags           = "ad.uac_flags"
	AttrADDistinguishedName  = "ad.distinguished_name"
)

// Machine inventory attributes added in contract v1.2 (additive MAY
// attributes on machine.discovered / machine.changed). The three hashes
// identify a container: the full engine container id, the engine-local
// image id (config digest, "sha256:…") and the registry content digest
// of the pulled manifest — the key vulnerability feeds match images on.
// The services pair describes what the machine offers: a JSON array of
// {name, category, version?, protocol?, port?, exposure?, source?} objects
// (model.MachineService) and, for cheap filtering, the sorted
// comma-joined set of categories drawn from AllowedServiceCategories.
const (
	AttrMachineContainerID       = "security.machine.container.id"
	AttrMachineImageID           = "security.machine.container.image.id"
	AttrMachineImageDigest       = "security.machine.container.image.digest"
	AttrMachineServices          = "security.machine.services"
	AttrMachineServiceCategories = "security.machine.service.categories"
)

// AllowedServiceCategories is the closed vocabulary of
// security.machine.service.categories members (model.ServiceCategory*).
var AllowedServiceCategories = map[string]struct{}{
	"directory":          {},
	"database":           {},
	"cache":              {},
	"search":             {},
	"message_queue":      {},
	"web":                {},
	"remote_access":      {},
	"file_sharing":       {},
	"object_storage":     {},
	"mail":               {},
	"dns":                {},
	"monitoring":         {},
	"identity":           {},
	"secrets":            {},
	"container_platform": {},
	"ci":                 {},
	"other":              {},
}

// AllowedAuditModules is the closed audit.<module> span suffix.
var AllowedAuditModules = map[string]struct{}{
	"ssh":         {},
	"firewall":    {},
	"permissions": {},
	"tls":         {},
}

// AllowedMachineTypes per §4.4.1.
var AllowedMachineTypes = map[string]struct{}{
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
	EventMachineDiscovered: {
		AttrEventDomain:                     {},
		AttrEventName:                       {},
		AttrScanUID:                         {},
		"security.machine.uid":              {},
		"security.machine.type":             {},
		"security.machine.name":             {},
		"security.machine.os.name":          {},
		"security.machine.os.version":       {},
		"security.machine.ip.v4":            {},
		"security.machine.ip.v6":            {},
		"security.machine.mac":              {},
		"security.machine.fqdn":             {},
		"security.machine.authorization":    {},
		"security.machine.managed_status":   {},
		"security.machine.first_seen":       {},
		"security.machine.discovery.source": {},
		AttrMachineContainerID:              {},
		AttrMachineImageID:                  {},
		AttrMachineImageDigest:              {},
		AttrMachineServices:                 {},
		AttrMachineServiceCategories:        {},
	},
	EventMachineChanged: {
		AttrEventDomain:                     {},
		AttrEventName:                       {},
		AttrScanUID:                         {},
		"security.machine.uid":              {},
		"security.machine.type":             {},
		"security.machine.name":             {},
		"security.machine.os.name":          {},
		"security.machine.os.version":       {},
		"security.machine.ip.v4":            {},
		"security.machine.ip.v6":            {},
		"security.machine.mac":              {},
		"security.machine.fqdn":             {},
		"security.machine.authorization":    {},
		"security.machine.managed_status":   {},
		"security.machine.first_seen":       {},
		"security.machine.discovery.source": {},
		"security.machine.change.field":     {},
		"security.machine.change.before":    {},
		"security.machine.change.after":     {},
		AttrMachineContainerID:              {},
		AttrMachineImageID:                  {},
		AttrMachineImageDigest:              {},
		AttrMachineServices:                 {},
		AttrMachineServiceCategories:        {},
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
		"security.machine.uid":              {},
		"security.machine.name":             {},
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
		"security.machine.uid":              {},
		"security.machine.name":             {},
	},
	EventScanLifecycle: {
		AttrEventDomain:             {},
		AttrEventName:               {},
		AttrScanUID:                 {},
		"security.scan.phase":       {},
		"security.scan.duration_ms": {},
		"security.scan.error.kind":  {},
	},
	EventProbeHeartbeat: {
		AttrEventDomain:       {},
		AttrEventName:         {},
		AttrScanUID:           {},
		AttrProbeSource:       {},
		AttrProbeStatus:       {},
		AttrProbeItemsEmitted: {},
		AttrProbeDurationMs:   {},
		AttrProbeBinaryHash:   {},
		AttrProbeSignature:    {},
	},
}

// EventRequiredAttributes lists the MUST-have keys for each event per
// §4.4.1–4.4.5. Missing keys cause the contract validator to fail.
var EventRequiredAttributes = map[EventName][]string{
	EventMachineDiscovered: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.machine.uid",
		"security.machine.type",
		"security.machine.name",
		"security.machine.authorization",
		"security.machine.managed_status",
		"security.machine.first_seen",
		"security.machine.discovery.source",
	},
	EventMachineChanged: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.machine.uid",
		"security.machine.type",
		"security.machine.name",
		"security.machine.authorization",
		"security.machine.managed_status",
		"security.machine.change.field",
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
		"security.machine.uid",
		"security.machine.name",
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
		"security.machine.uid",
		"security.machine.name",
	},
	EventScanLifecycle: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		"security.scan.phase",
	},
	EventProbeHeartbeat: {
		AttrEventDomain,
		AttrEventName,
		AttrScanUID,
		AttrProbeSource,
		AttrProbeStatus,
		AttrProbeBinaryHash,
		AttrProbeSignature,
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
	"kite.discovery.machines.found": {
		Name: "kite.discovery.machines.found", Kind: MetricKindCounter, Unit: "{machine}",
		Labels: []string{"discovery.source"},
	},
	"kite.discovery.errors.count": {
		Name: "kite.discovery.errors.count", Kind: MetricKindCounter, Unit: "{error}",
		Labels: []string{"discovery.source", "error.kind"},
	},
	"kite.machines.total": {
		Name: "kite.machines.total", Kind: MetricKindUpDownCounter, Unit: "{machine}",
		Labels: []string{"machine.type", "authorization"},
	},
	"kite.machines.stale": {
		Name: "kite.machines.stale", Kind: MetricKindUpDownCounter, Unit: "{machine}",
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
	"security.machine.uid":       1_000_000,
	"security.machine.fqdn":      200_000,
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
// the given event name. The per-record signature attributes are permitted on
// every declared event.
func IsAllowedEventAttribute(event EventName, key string) bool {
	allowed, ok := EventAttributes[event]
	if !ok {
		return false
	}
	if _, found := recordSignatureAttributes[key]; found {
		return true
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
