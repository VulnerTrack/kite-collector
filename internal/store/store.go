package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// AssetFilter constrains which assets are returned by ListAssets.
type AssetFilter struct {
	AssetType    string
	IsAuthorized string
	IsManaged    string
	Hostname     string
	Limit        int
	Offset       int
}

// EventFilter constrains which events are returned by ListEvents.
type EventFilter struct {
	AssetID   *uuid.UUID
	ScanRunID *uuid.UUID
	EventType string
	Limit     int
	Offset    int
}

// Store defines the persistence interface for the kite-collector.
// Implementations must be safe for concurrent use.
type Store interface {
	// UpsertAsset inserts a new asset or updates an existing one matched by
	// the UNIQUE(hostname, asset_type) constraint.
	UpsertAsset(ctx context.Context, asset model.Asset) error

	// UpsertAssets atomically upserts a batch of assets inside a single
	// transaction and returns the number of inserts and updates performed.
	UpsertAssets(ctx context.Context, assets []model.Asset) (inserted, updated int, err error)

	// GetAssetByNaturalKey retrieves the asset whose SHA-256 natural key
	// (hostname|asset_type) matches key. Returns nil when not found.
	GetAssetByNaturalKey(ctx context.Context, key string) (*model.Asset, error)

	// ListAssets returns assets matching the supplied filter.
	ListAssets(ctx context.Context, filter AssetFilter) ([]model.Asset, error)

	// GetStaleAssets returns assets whose last_seen_at is older than
	// time.Now().Add(-threshold).
	GetStaleAssets(ctx context.Context, threshold time.Duration) ([]model.Asset, error)

	// InsertEvent persists a single asset lifecycle event.
	InsertEvent(ctx context.Context, event model.AssetEvent) error

	// InsertEvents persists a batch of asset lifecycle events.
	InsertEvents(ctx context.Context, events []model.AssetEvent) error

	// ListEvents returns events matching the supplied filter.
	ListEvents(ctx context.Context, filter EventFilter) ([]model.AssetEvent, error)

	// CreateScanRun records a new scan run with status "running".
	CreateScanRun(ctx context.Context, run model.ScanRun) error

	// CompleteScanRun updates the scan run identified by id with the final
	// result counters and marks it completed (or failed on error).
	CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error

	// GetLatestScanRun returns the most recent scan run by started_at, or
	// nil when no scan runs exist.
	GetLatestScanRun(ctx context.Context) (*model.ScanRun, error)

	// Migrate creates the schema tables and indexes if they do not exist.
	Migrate(ctx context.Context) error

	// Close releases all resources held by the store.
	Close() error
}
