package connectorkit

import "github.com/vulnertrack/kite-collector/internal/safenet"

// NewGuard returns a safenet.PaginationGuardV2 pre-labelled with the connector's
// source name so guard-trip events (ConnectorGuardEvent, 4.2.6) and the
// kite_pagination_truncated_total counter carry correct per-connector
// attribution. Every connector constructs one guard per pagination loop (outside
// the loop) and calls NextPage with each fetched page's byte length.
func NewGuard(sourceName string) *safenet.PaginationGuardV2 {
	return safenet.NewPaginationGuardV2WithSource(sourceName)
}
