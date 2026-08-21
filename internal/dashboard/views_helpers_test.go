package dashboard

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

func TestRenderCell(t *testing.T) {
	assert.Equal(t, "", renderCell(nil))
	assert.Equal(t, "text", renderCell("text"))
	assert.Equal(t, "", renderCell([]byte{}))
	assert.Equal(t, "deadbeef", renderCell([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.Equal(t, "<65 bytes>", renderCell(make([]byte, 65)),
		"blobs past 64 bytes render as a placeholder, not hex")
	assert.Equal(t, "true", renderCell(true))
	assert.Equal(t, "false", renderCell(false))
	assert.Equal(t, "42", renderCell(int64(42)))
	assert.Contains(t, renderCell(time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)), "2026-08-21")
}

func TestFindFK(t *testing.T) {
	fks := []store.ForeignKey{
		{FromColumn: "machine_id", ToTable: "machines", ToColumn: "id"},
		{FromColumn: "scan_run_id", ToTable: "scan_runs", ToColumn: "id"},
	}
	fk := findFK(fks, "scan_run_id")
	require.NotNil(t, fk)
	assert.Equal(t, "scan_runs", fk.ToTable)
	assert.Nil(t, findFK(fks, "hostname"), "uncovered columns yield nil")
	assert.Nil(t, findFK(nil, "x"))
}

func TestRowKeyQuery(t *testing.T) {
	assert.Empty(t, rowKeyQuery(nil))
	q := rowKeyQuery(map[string]string{"id": "abc"})
	assert.Equal(t, "pk.id=abc", q)
}

func TestRowCountBucket(t *testing.T) {
	assert.NotEqual(t, rowCountBucket(0), rowCountBucket(100000),
		"empty and huge tables land in different buckets")
}

// suggestJoinColumns preference order: join-side FK, base-side FK,
// id/machine_id conventions, then primary-key/first-column fallback.
func TestSuggestJoinColumns(t *testing.T) {
	base := &store.TableSchema{
		Name:       "machines",
		PrimaryKey: []string{"id"},
		Columns:    []store.ColumnSchema{{Name: "id"}, {Name: "hostname"}},
	}
	join := &store.TableSchema{
		Name:       "network_interfaces",
		PrimaryKey: []string{"id"},
		Columns:    []store.ColumnSchema{{Name: "id"}, {Name: "machine_id"}},
		ForeignKeys: []store.ForeignKey{
			{FromColumn: "machine_id", ToTable: "machines", ToColumn: "id"},
		},
	}
	onBase, onJoin := suggestJoinColumns(base, join)
	assert.Equal(t, "id", onBase, "join-side FK wins")
	assert.Equal(t, "machine_id", onJoin)

	// Base-side FK.
	b2 := &store.TableSchema{
		Name:        "events",
		ForeignKeys: []store.ForeignKey{{FromColumn: "machine_id", ToTable: "machines", ToColumn: "id"}},
		Columns:     []store.ColumnSchema{{Name: "machine_id"}},
	}
	m2 := &store.TableSchema{Name: "machines", Columns: []store.ColumnSchema{{Name: "id"}}}
	onBase, onJoin = suggestJoinColumns(b2, m2)
	assert.Equal(t, "machine_id", onBase)
	assert.Equal(t, "id", onJoin)

	// Convention fallback: base has id, join has machine_id, no FKs.
	onBase, onJoin = suggestJoinColumns(
		&store.TableSchema{Name: "a", Columns: []store.ColumnSchema{{Name: "id"}}},
		&store.TableSchema{Name: "b", Columns: []store.ColumnSchema{{Name: "machine_id"}}})
	assert.Equal(t, "id", onBase)
	assert.Equal(t, "machine_id", onJoin)

	// Reverse convention.
	onBase, onJoin = suggestJoinColumns(
		&store.TableSchema{Name: "a", Columns: []store.ColumnSchema{{Name: "machine_id"}}},
		&store.TableSchema{Name: "b", Columns: []store.ColumnSchema{{Name: "id"}}})
	assert.Equal(t, "machine_id", onBase)
	assert.Equal(t, "id", onJoin)

	// Last resort: primary key, else first column.
	onBase, onJoin = suggestJoinColumns(
		&store.TableSchema{Name: "a", PrimaryKey: []string{"pk_a"}, Columns: []store.ColumnSchema{{Name: "pk_a"}}},
		&store.TableSchema{Name: "b", Columns: []store.ColumnSchema{{Name: "first_col"}}})
	assert.Equal(t, "pk_a", onBase)
	assert.Equal(t, "first_col", onJoin)
}

// renderSoftwareFragment and renderRowReportFragment over a real seeded
// store: the fragments render actual data, and the row report resolves
// a primary key round-tripped through rowKeyQuery semantics.
func TestRenderSoftwareAndRowReportFragments(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	m := model.Machine{
		ID:           uuid.Must(uuid.NewV7()),
		Hostname:     "sw-host",
		MachineType:  model.MachineTypeServer,
		IsAuthorized: model.AuthorizationUnknown,
		IsManaged:    model.ManagedUnknown,
		FirstSeenAt:  time.Now().UTC(),
		LastSeenAt:   time.Now().UTC(),
	}
	require.NoError(t, st.UpsertMachine(ctx, m))
	require.NoError(t, st.UpsertSoftware(ctx, m.ID, []model.InstalledSoftware{{
		ID:           uuid.Must(uuid.NewV7()),
		SoftwareName: "nginx",
		Version:      "1.25.4",
	}}))

	var buf bytes.Buffer
	require.NoError(t, renderSoftwareFragment(&buf, ctx, st, testContext()))
	assert.Contains(t, buf.String(), "nginx")
	assert.Contains(t, buf.String(), "1.25.4")

	buf.Reset()
	err := renderRowReportFragment(&buf, ctx, st, "machines", map[string]string{"id": m.ID.String()})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "sw-host")

	err = renderRowReportFragment(&bytes.Buffer{}, ctx, st, "no_such_table", map[string]string{"id": "x"})
	require.Error(t, err, "unknown tables must fail loudly")
}
