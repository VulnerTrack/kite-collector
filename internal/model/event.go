package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AssetEvent records a lifecycle event associated with an asset.
type AssetEvent struct {
	Timestamp       time.Time          `json:"timestamp"`
	EventType       EventType          `json:"event_type"`
	Severity        Severity           `json:"severity"`
	Details         string             `json:"details"` // JSON
	TraceID         string             `json:"trace_id,omitempty"`
	SpanID          string             `json:"span_id,omitempty"`
	Hostname        string             `json:"hostname,omitempty"`
	AssetType       AssetType          `json:"asset_type,omitempty"`
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
	ID              uuid.UUID          `json:"id"`
	AssetID         uuid.UUID          `json:"asset_id"`
	ScanRunID       uuid.UUID          `json:"scan_run_id"`
}

// BuildEventDetails returns a compact JSON-encoded summary of an asset event
// suitable for placement in AssetEvent.Details and surfacing as the OTLP log
// record body for human triage. Only fields that are non-empty (or non-zero
// for timestamps) on the asset are included; event_type and asset_id are
// always present.
//
// The helper deliberately returns only a string (no error) — the encoded
// payload is a flat map[string]string and json.Marshal cannot fail for that
// shape. In the unlikely event the marshal somehow errors, we fall back to a
// minimal hand-written JSON document so that consumers always receive a valid
// JSON body.
func BuildEventDetails(a Asset, eventType EventType) string {
	details := make(map[string]string, 14)
	details["event_type"] = string(eventType)
	details["event_name"] = eventType.Name()
	details["asset_id"] = a.ID.String()

	if a.Hostname != "" {
		details["hostname"] = a.Hostname
	}
	if a.AssetType != "" {
		details["asset_type"] = string(a.AssetType)
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
		return `{"event_type":"` + string(eventType) + `","asset_id":"` + a.ID.String() + `"}`
	}
	return string(encoded)
}

// FromAsset copies identifying fields from an Asset into the event so that
// consumers (e.g. the OTLP emitter) have full context without a store lookup.
func (e *AssetEvent) FromAsset(a Asset) {
	e.AssetID = a.ID
	e.Hostname = a.Hostname
	e.AssetType = a.AssetType
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
}
