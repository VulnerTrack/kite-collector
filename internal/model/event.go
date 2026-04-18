package model

import (
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
