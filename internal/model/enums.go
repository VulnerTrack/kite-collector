package model

import "strings"

// MachineType classifies the kind of machine discovered on the network.
type MachineType string

const (
	MachineTypeServer          MachineType = "server"
	MachineTypeWorkstation     MachineType = "workstation"
	MachineTypeNetworkDevice   MachineType = "network_device"
	MachineTypeCloudInstance   MachineType = "cloud_instance"
	MachineTypeContainer       MachineType = "container"
	MachineTypeVirtualMachine  MachineType = "virtual_machine"
	MachineTypeIOTDevice       MachineType = "iot_device"
	MachineTypeAppliance       MachineType = "appliance"
	MachineTypeSoftwareProject MachineType = "software_project"
	MachineTypeRepository      MachineType = "repository"
)

// Valid returns true when the MachineType is one of the recognised values.
func (a MachineType) Valid() bool {
	switch a {
	case MachineTypeServer,
		MachineTypeWorkstation,
		MachineTypeNetworkDevice,
		MachineTypeCloudInstance,
		MachineTypeContainer,
		MachineTypeVirtualMachine,
		MachineTypeIOTDevice,
		MachineTypeAppliance,
		MachineTypeSoftwareProject,
		MachineTypeRepository:
		return true
	default:
		return false
	}
}

// AuthorizationState indicates whether an machine is authorised to be on the network.
type AuthorizationState string

const (
	AuthorizationUnknown      AuthorizationState = "unknown"
	AuthorizationAuthorized   AuthorizationState = "authorized"
	AuthorizationUnauthorized AuthorizationState = "unauthorized"
)

// ManagedState indicates whether an machine is under management by the organisation.
type ManagedState string

const (
	ManagedUnknown   ManagedState = "unknown"
	ManagedManaged   ManagedState = "managed"
	ManagedUnmanaged ManagedState = "unmanaged"
)

// Severity represents the impact level assigned to an event or finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EventType identifies the kind of lifecycle event recorded for an machine.
type EventType string

const (
	EventMachineDiscovered           EventType = "MachineDiscovered"
	EventMachineUpdated              EventType = "MachineUpdated"
	EventMachineAnalyzed             EventType = "MachineAnalyzed"
	EventUnauthorizedMachineDetected EventType = "UnauthorizedMachineDetected"
	EventUnmanagedMachineDetected    EventType = "UnmanagedMachineDetected"
	EventMachineNotSeen              EventType = "MachineNotSeen"
	EventMachineRemoved              EventType = "MachineRemoved"
)

// Name returns the stable, namespaced wire name for an event type, suitable
// for the OpenTelemetry LogRecord.eventName field (proto v1.5+) and for
// indexing in downstream backends. Unlike String() (which returns the
// CamelCase constant value), Name() returns a dotted, snake_case identifier
// in the "kite.machine.*" namespace.
//
// Unknown values fall through to a "kite.machine.unknown.<lowercased>" form so
// that ad-hoc or future event types remain parseable rather than empty.
func (e EventType) Name() string {
	switch e {
	case EventMachineDiscovered:
		return "kite.machine.discovered"
	case EventMachineUpdated:
		return "kite.machine.updated"
	case EventMachineAnalyzed:
		return "kite.machine.analyzed"
	case EventUnauthorizedMachineDetected:
		return "kite.machine.unauthorized_detected"
	case EventUnmanagedMachineDetected:
		return "kite.machine.unmanaged_detected"
	case EventMachineNotSeen:
		return "kite.machine.not_seen"
	case EventMachineRemoved:
		return "kite.machine.removed"
	default:
		return "kite.machine.unknown." + strings.ToLower(string(e))
	}
}

// ScanStatus tracks the lifecycle state of a scan run.
type ScanStatus string

const (
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusTimedOut  ScanStatus = "timed_out"
)
