package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MachineEvent records a lifecycle event associated with an machine.
type MachineEvent struct {
	Timestamp       time.Time          `json:"timestamp"`
	EventType       EventType          `json:"event_type"`
	Severity        Severity           `json:"severity"`
	Details         string             `json:"details"` // JSON
	TraceID         string             `json:"trace_id,omitempty"`
	SpanID          string             `json:"span_id,omitempty"`
	Hostname        string             `json:"hostname,omitempty"`
	MachineType     MachineType        `json:"machine_type,omitempty"`
	OSFamily        string             `json:"os_family,omitempty"`
	OSVersion       string             `json:"os_version,omitempty"`
	KernelVersion   string             `json:"kernel_version,omitempty"`
	Architecture    string             `json:"architecture,omitempty"`
	Environment     string             `json:"environment,omitempty"`
	Owner           string             `json:"owner,omitempty"`
	Criticality     string             `json:"criticality,omitempty"`
	DiscoverySource string             `json:"discovery_source,omitempty"`
	IsAuthorized    AuthorizationState `json:"is_authorized,omitempty"`
	IsManaged       ManagedState       `json:"is_managed,omitempty"`
	FirstSeenAt     time.Time          `json:"first_seen_at,omitempty"`
	ID              uuid.UUID          `json:"id"`
	MachineID       uuid.UUID          `json:"machine_id"`
	ScanRunID       uuid.UUID          `json:"scan_run_id"`
}

// BuildEventDetails returns a compact JSON-encoded summary of an machine event
// suitable for placement in MachineEvent.Details and surfacing as the OTLP log
// record body for human triage. Only fields that are non-empty (or non-zero
// for timestamps) on the machine are included; event_type and machine_id are
// always present.
//
// The helper deliberately returns only a string (no error) — the encoded
// payload is a flat map[string]string and json.Marshal cannot fail for that
// shape. In the unlikely event the marshal somehow errors, we fall back to a
// minimal hand-written JSON document so that consumers always receive a valid
// JSON body.
func BuildEventDetails(a Machine, eventType EventType) string {
	details := make(map[string]string, 14)
	details["event_type"] = string(eventType)
	details["event_name"] = eventType.Name()
	details["machine_id"] = a.ID.String()

	if a.Hostname != "" {
		details["hostname"] = a.Hostname
	}
	if a.MachineType != "" {
		details["machine_type"] = string(a.MachineType)
	}
	if a.OSFamily != "" {
		details["os_family"] = a.OSFamily
	}
	if a.Environment != "" {
		details["environment"] = a.Environment
	}
	if a.Owner != "" {
		details["owner"] = a.Owner
	}
	if a.Criticality != "" {
		details["criticality"] = a.Criticality
	}
	if a.DiscoverySource != "" {
		details["discovery_source"] = a.DiscoverySource
	}
	if a.IsAuthorized != "" {
		details["is_authorized"] = string(a.IsAuthorized)
	}
	if a.IsManaged != "" {
		details["is_managed"] = string(a.IsManaged)
	}
	if !a.FirstSeenAt.IsZero() {
		details["first_seen_at"] = a.FirstSeenAt.Format(time.RFC3339)
	}
	if !a.LastSeenAt.IsZero() {
		details["last_seen_at"] = a.LastSeenAt.Format(time.RFC3339)
	}

	encoded, err := json.Marshal(details)
	if err != nil {
		// json.Marshal cannot fail for map[string]string, but stay safe.
		return `{"event_type":"` + string(eventType) + `","machine_id":"` + a.ID.String() + `"}`
	}
	return string(encoded)
}

// FromMachine copies identifying fields from an Machine into the event so that
// consumers (e.g. the OTLP emitter) have full context without a store lookup.
func (e *MachineEvent) FromMachine(a Machine) {
	e.MachineID = a.ID
	e.Hostname = a.Hostname
	e.MachineType = a.MachineType
	e.OSFamily = a.OSFamily
	e.OSVersion = a.OSVersion
	e.KernelVersion = a.KernelVersion
	e.Architecture = a.Architecture
	e.Environment = a.Environment
	e.Owner = a.Owner
	e.Criticality = a.Criticality
	e.DiscoverySource = a.DiscoverySource
	e.IsAuthorized = a.IsAuthorized
	e.IsManaged = a.IsManaged
	e.FirstSeenAt = a.FirstSeenAt
}
