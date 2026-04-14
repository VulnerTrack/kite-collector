//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/postgres"
)

// startPostgresContainer launches a PostgreSQL 16 container and returns the
// DSN. The container is terminated when the test completes.
func startPostgresContainer(ctx context.Context, t *testing.T) string {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "kite",
			"POSTGRES_PASSWORD": "kite",
			"POSTGRES_DB":       "kite_e2e",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	return fmt.Sprintf("postgres://kite:kite@%s:%s/kite_e2e?sslmode=disable", host, port.Port())
}

// newTestStore creates a PostgresStore connected to the given DSN, runs
// migrations, and registers cleanup.
func newTestStore(t *testing.T, dsn string) *postgres.PostgresStore {
	t.Helper()

	st, err := postgres.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	require.NoError(t, st.Migrate(context.Background()))
	return st
}

// makeAsset builds a minimal valid Asset with a computed natural key.
func makeAsset(hostname string, assetType model.AssetType, ts time.Time) model.Asset {
	a := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       assetType,
		OSFamily:        "linux",
		OSVersion:       "6.1",
		Environment:     "e2e-test",
		Owner:           "secops",
		Criticality:     "high",
		DiscoverySource: "e2e",
		FirstSeenAt:     ts,
		LastSeenAt:      ts,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            "[]",
	}
	a.ComputeNaturalKey()
	return a
}

// makeEvent builds a minimal valid AssetEvent.
func makeEvent(assetID, scanRunID uuid.UUID, eventType model.EventType, ts time.Time) model.AssetEvent {
	return model.AssetEvent{
		ID:        uuid.Must(uuid.NewV7()),
		AssetID:   assetID,
		ScanRunID: scanRunID,
		EventType: eventType,
		Severity:  model.SeverityLow,
		Timestamp: ts,
		Details:   `{"source":"e2e"}`,
	}
}
