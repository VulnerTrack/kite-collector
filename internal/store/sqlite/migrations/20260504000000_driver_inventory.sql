-- 20260504000000_driver_inventory.sql: durable storage for kernel module
-- and device driver enumeration introduced by RFC-0128.
--
-- Two additive tables. No existing rows or columns are touched.
--
--   loaded_drivers    — one row per (asset_id, name, version) observed
--                       loaded driver. Hash columns are populated only
--                       on platforms where the underlying source exposes
--                       them (e.g. Authentihash on Windows, ELF SHA-256
--                       on Linux). taint_flags / dependencies are stored
--                       as JSON arrays so the DBOS bridge can replay them
--                       to ClickHouse without an extra join.
--
--   device_bindings   — one row per (asset_id, bus, address) PCI/USB/PnP
--                       hardware-to-driver binding. driver_id may be NULL
--                       when the kernel reports no bound driver (e.g. a
--                       PCI function with no module loaded).
--
-- Sync watermarks are NULL on insert and stamped to unixepoch() once the
-- DBOS workflow has confirmed the row is in ClickHouse.

CREATE TABLE IF NOT EXISTS loaded_drivers (
    id                TEXT PRIMARY KEY NOT NULL,
    asset_id          TEXT NOT NULL,
    name              TEXT NOT NULL,
    display_name      TEXT,
    path              TEXT,
    version           TEXT,
    vendor            TEXT,
    signer            TEXT,
    signature_state   TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (signature_state IN (
                          'valid', 'expired', 'revoked',
                          'catalog', 'unsigned', 'unknown'
                      )),
    signature_algo    TEXT,
    driver_framework  TEXT NOT NULL,
    start_mode        TEXT,
    state             TEXT,
    architecture      TEXT,
    on_disk_sha256    TEXT,
    authentihash      TEXT,
    import_hash       TEXT,
    cpe23             TEXT,
    description       TEXT,
    taint_flags_json  TEXT NOT NULL DEFAULT '[]',
    dependencies_json TEXT NOT NULL DEFAULT '[]',
    loaded_at         TEXT,
    collected_at      TEXT NOT NULL,
    synced_at         INTEGER,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_loaded_drivers_unique
    ON loaded_drivers(asset_id, name, version);

CREATE INDEX IF NOT EXISTS idx_loaded_drivers_unsynced
    ON loaded_drivers(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_loaded_drivers_asset
    ON loaded_drivers(asset_id);

CREATE INDEX IF NOT EXISTS idx_loaded_drivers_sha256
    ON loaded_drivers(on_disk_sha256)
    WHERE on_disk_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_loaded_drivers_authentihash
    ON loaded_drivers(authentihash)
    WHERE authentihash IS NOT NULL;

CREATE TABLE IF NOT EXISTS device_bindings (
    id              TEXT PRIMARY KEY NOT NULL,
    asset_id        TEXT NOT NULL,
    driver_id       TEXT REFERENCES loaded_drivers(id),
    bus             TEXT NOT NULL,
    address         TEXT NOT NULL,
    vendor_id       TEXT,
    device_id       TEXT,
    subsystem_vid   TEXT,
    subsystem_did   TEXT,
    class           TEXT,
    driver_name     TEXT,
    hardware_id     TEXT,
    collected_at    TEXT NOT NULL,
    synced_at       INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_bindings_unique
    ON device_bindings(asset_id, bus, address);

CREATE INDEX IF NOT EXISTS idx_device_bindings_unsynced
    ON device_bindings(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_device_bindings_driver
    ON device_bindings(driver_id);
