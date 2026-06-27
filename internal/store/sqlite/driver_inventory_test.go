package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/driver"
)

func TestWriteLoadedDrivers_InsertAndUpdate(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	asset := uuid.Must(uuid.NewV7())

	drv := driver.LoadedDriver{
		Name:            "rwdrv",
		DisplayName:     "Read Write Driver",
		Path:            "/lib/modules/rwdrv.ko",
		Version:         "1.2.3",
		SignatureState:  driver.SignatureUnsigned,
		DriverFramework: driver.FrameworkLinuxModule,
		OnDiskSHA256:    "abcd",
		TaintFlags:      []string{"OE", "P"},
		Dependencies:    []string{"libcrc32c"},
		CollectedAt:     time.Now().UTC(),
	}
	ids, err := s.WriteLoadedDrivers(ctx, asset, []driver.LoadedDriver{drv})
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.NotEqual(t, uuid.Nil, ids[0])

	rows, err := s.ListLoadedDrivers(ctx, LoadedDriverFilter{AssetID: asset.String()})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "rwdrv", rows[0].Name)
	assert.Equal(t, `["OE","P"]`, rows[0].TaintFlagsJSON)
	assert.Equal(t, `["libcrc32c"]`, rows[0].DependenciesRaw)
	require.NotNil(t, rows[0].OnDiskSHA256)
	assert.Equal(t, "abcd", *rows[0].OnDiskSHA256)

	// Re-write with same (asset, name, version) -> upsert.
	drv.Vendor = "Acme Inc"
	_, err = s.WriteLoadedDrivers(ctx, asset, []driver.LoadedDriver{drv})
	require.NoError(t, err)

	rows, err = s.ListLoadedDrivers(ctx, LoadedDriverFilter{AssetID: asset.String()})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].Vendor)
	assert.Equal(t, "Acme Inc", *rows[0].Vendor)
}

func TestWriteLoadedDrivers_PreservesProvidedID(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	asset := uuid.Must(uuid.NewV7())
	preset := uuid.Must(uuid.NewV7())

	drv := driver.LoadedDriver{
		ID:              preset,
		Name:            "preset",
		Version:         "1",
		SignatureState:  driver.SignatureValid,
		DriverFramework: driver.FrameworkLinuxModule,
		CollectedAt:     time.Now().UTC(),
	}
	ids, err := s.WriteLoadedDrivers(ctx, asset, []driver.LoadedDriver{drv})
	require.NoError(t, err)
	assert.Equal(t, preset, ids[0])
}

func TestWriteLoadedDrivers_EmptyIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ids, err := s.WriteLoadedDrivers(
		context.Background(), uuid.Must(uuid.NewV7()), nil,
	)
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestWriteLoadedDrivers_RejectsNilAssetID(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	_, err := s.WriteLoadedDrivers(context.Background(), uuid.Nil,
		[]driver.LoadedDriver{{Name: "x"}})
	require.Error(t, err)
}

func TestWriteDeviceBindings_InsertAndUpdate(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	asset := uuid.Must(uuid.NewV7())

	// First persist a driver so we can FK from the binding.
	drv := driver.LoadedDriver{
		Name:            "nvidia",
		Version:         "535.183.01",
		SignatureState:  driver.SignatureUnsigned,
		DriverFramework: driver.FrameworkLinuxModule,
		CollectedAt:     time.Now().UTC(),
	}
	driverIDs, err := s.WriteLoadedDrivers(ctx, asset, []driver.LoadedDriver{drv})
	require.NoError(t, err)
	require.Len(t, driverIDs, 1)

	bind := driver.DeviceBinding{
		Bus:        "pci",
		Address:    "0000:01:00.0",
		VendorID:   "10de",
		DeviceID:   "2204",
		Class:      "030000",
		DriverName: "nvidia",
		HardwareID: "PCI\\VEN_10DE&DEV_2204",
		DriverID:   driverIDs[0],
	}
	require.NoError(t, s.WriteDeviceBindings(ctx, asset, []driver.DeviceBinding{bind}))

	rows, err := s.ListDeviceBindings(ctx, DeviceBindingFilter{AssetID: asset.String()})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "pci", rows[0].Bus)
	require.NotNil(t, rows[0].DriverID)
	assert.Equal(t, driverIDs[0].String(), *rows[0].DriverID)

	// Upsert: same (asset, bus, address) replaces the row.
	bind.Class = "030200"
	require.NoError(t, s.WriteDeviceBindings(ctx, asset, []driver.DeviceBinding{bind}))
	rows, err = s.ListDeviceBindings(ctx, DeviceBindingFilter{AssetID: asset.String()})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].Class)
	assert.Equal(t, "030200", *rows[0].Class)
}

func TestWriteDeviceBindings_NilDriverIDStoredAsNull(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	asset := uuid.Must(uuid.NewV7())

	bind := driver.DeviceBinding{Bus: "usb", Address: "1-1", VendorID: "abcd"}
	require.NoError(t, s.WriteDeviceBindings(ctx, asset, []driver.DeviceBinding{bind}))

	rows, err := s.ListDeviceBindings(ctx, DeviceBindingFilter{AssetID: asset.String()})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].DriverID)
}

func TestMarkLoadedDriversSynced_StampsTimestamp(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	asset := uuid.Must(uuid.NewV7())

	drv := driver.LoadedDriver{
		Name:            "syncme",
		SignatureState:  driver.SignatureUnknown,
		DriverFramework: driver.FrameworkLinuxModule,
		CollectedAt:     time.Now().UTC(),
	}
	ids, err := s.WriteLoadedDrivers(ctx, asset, []driver.LoadedDriver{drv})
	require.NoError(t, err)
	require.Len(t, ids, 1)

	require.NoError(t, s.MarkLoadedDriversSynced(ctx, []string{ids[0].String()}))

	var synced *int64
	require.NoError(t, s.db.QueryRowContext(
		ctx, `SELECT synced_at FROM loaded_drivers WHERE id = ?`, ids[0].String(),
	).Scan(&synced))
	require.NotNil(t, synced)
	assert.Greater(t, *synced, int64(0))
}

func TestMarkSynced_EmptyIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	require.NoError(t, s.MarkLoadedDriversSynced(context.Background(), nil))
	require.NoError(t, s.MarkDeviceBindingsSynced(context.Background(), nil))
}

func TestEncodeStringArray_EmptyAndPopulated(t *testing.T) {
	t.Parallel()
	got, err := encodeStringArray(nil)
	require.NoError(t, err)
	assert.Equal(t, "[]", got)

	got, err = encodeStringArray([]string{"a", "b"})
	require.NoError(t, err)
	assert.Equal(t, `["a","b"]`, got)
}

func TestListLoadedDrivers_FilterByAssetIDIsolatesRows(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	a := uuid.Must(uuid.NewV7())
	b := uuid.Must(uuid.NewV7())

	mk := func(name string) driver.LoadedDriver {
		return driver.LoadedDriver{
			Name:            name,
			SignatureState:  driver.SignatureUnknown,
			DriverFramework: driver.FrameworkLinuxModule,
			CollectedAt:     time.Now().UTC(),
		}
	}
	_, err := s.WriteLoadedDrivers(ctx, a, []driver.LoadedDriver{mk("d-a")})
	require.NoError(t, err)
	_, err = s.WriteLoadedDrivers(ctx, b, []driver.LoadedDriver{mk("d-b")})
	require.NoError(t, err)

	rowsA, err := s.ListLoadedDrivers(ctx, LoadedDriverFilter{AssetID: a.String()})
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, "d-a", rowsA[0].Name)

	rowsAll, err := s.ListLoadedDrivers(ctx, LoadedDriverFilter{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, rowsAll, 2)
}
