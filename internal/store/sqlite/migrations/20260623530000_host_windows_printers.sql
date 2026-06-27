-- 20260623530000_host_windows_printers.sql: per-host Windows printer
-- inventory introduced by CDMS iter 46.
--
-- Two related tables in one migration:
--
--   host_windows_printers       — one row per Win32_Printer.
--                                 Captures driver, share state, default
--                                 flag, runtime status.
--
--   host_windows_printer_ports  — one row per Win32_TCPIPPrinterPort.
--                                 Captures IP / port / protocol / SNMP.
--
-- Audit value (MITRE T1210 — Exploitation of Remote Services,
-- defender side):
--   - `is_network_printer=1 AND port_protocol IN (1, 2)` flags
--     network-attached printers — the audit pipeline joins against
--     CVE feeds for Lexmark/HP/Xerox/Brother firmware exposures.
--   - `is_shared=1` flags printers exposing an SMB share, lateral-
--     movement adjacent.
--   - `snmp_enabled=1 AND snmp_community='public'` is the classic
--     lateral-recon enabler the audit pipeline alerts on.
--   - Cross-reference port.host_address against host_listeners +
--     host_intranet_webs to identify printers running embedded web
--     management UIs (which then need their own audit).

CREATE TABLE IF NOT EXISTS host_windows_printers (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'powershell-cim', 'powershell-wmi', 'unknown'
                        )),
    name                TEXT NOT NULL,
    driver_name         TEXT,
    port_name           TEXT,
    location            TEXT,
    comment             TEXT,
    server_name         TEXT,
    share_name          TEXT,
    is_local            INTEGER NOT NULL DEFAULT 0
                        CHECK (is_local IN (0, 1)),
    is_network_printer  INTEGER NOT NULL DEFAULT 0
                        CHECK (is_network_printer IN (0, 1)),
    is_shared           INTEGER NOT NULL DEFAULT 0
                        CHECK (is_shared IN (0, 1)),
    is_default          INTEGER NOT NULL DEFAULT 0
                        CHECK (is_default IN (0, 1)),
    is_published        INTEGER NOT NULL DEFAULT 0
                        CHECK (is_published IN (0, 1)),
    printer_status      INTEGER NOT NULL DEFAULT 0,
                        -- 1=Other, 2=Unknown, 3=Idle, 4=Printing, 5=Warmup, 6=Stopped, 7=Offline
    printer_state       INTEGER NOT NULL DEFAULT 0,
    detected_error_state INTEGER NOT NULL DEFAULT 0,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_printers_unique
    ON host_windows_printers(asset_id, name);

CREATE INDEX IF NOT EXISTS idx_host_windows_printers_unsynced
    ON host_windows_printers(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_host_windows_printers_shared
    ON host_windows_printers(asset_id, share_name)
    WHERE is_shared = 1;

CREATE INDEX IF NOT EXISTS idx_host_windows_printers_network
    ON host_windows_printers(asset_id, port_name)
    WHERE is_network_printer = 1;

CREATE TABLE IF NOT EXISTS host_windows_printer_ports (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'powershell-cim', 'powershell-wmi', 'unknown'
                        )),
    name                TEXT NOT NULL,         -- matches Win32_Printer.PortName
    host_address        TEXT,                  -- IP / DNS name
    port_number         INTEGER NOT NULL DEFAULT 0,
    port_protocol       INTEGER NOT NULL DEFAULT 0,
                        -- 1 = RAW (port 9100), 2 = LPR
    description         TEXT,
    snmp_enabled        INTEGER NOT NULL DEFAULT 0
                        CHECK (snmp_enabled IN (0, 1)),
    snmp_community      TEXT,
    is_default_community INTEGER NOT NULL DEFAULT 0
                        CHECK (is_default_community IN (0, 1)),
    queue_name          TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_printer_ports_unique
    ON host_windows_printer_ports(asset_id, name);

CREATE INDEX IF NOT EXISTS idx_host_windows_printer_ports_unsynced
    ON host_windows_printer_ports(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me ports with default SNMP community (public)".
CREATE INDEX IF NOT EXISTS idx_host_windows_printer_ports_default_community
    ON host_windows_printer_ports(asset_id, host_address)
    WHERE is_default_community = 1;
