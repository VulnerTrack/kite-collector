-- host_linux_flatpak inventories Linux Flatpak metadata
-- cached on workstations across any distro running flatpak
-- (Fedora Workstation default, Ubuntu via apt, Manjaro,
-- openSUSE, Pop!_OS, Steam Deck SteamOS, etc.).
--
-- Each installed Flatpak app exposes:
--
--   /var/lib/flatpak/app/<app-id>/current/active/metadata
--   /var/lib/flatpak/exports/share/metainfo/<app-id>.metainfo.xml
--   /var/lib/flatpak/exports/share/applications/<app-id>.desktop
--   /var/lib/flatpak/repo/refs/...
--   ~/.local/share/flatpak/app/<app-id>/...   per-user installs
--
-- The `metadata` file uses INI syntax with sections like
-- [Application] (carrying name + runtime + command) and
-- [Context] (declaring filesystem/device/socket permissions):
--
--   [Application]
--   name=org.mozilla.firefox
--   runtime=org.freedesktop.Platform/x86_64/23.08
--   sdk=org.freedesktop.Sdk/x86_64/23.08
--   command=firefox
--
--   [Context]
--   shared=network;ipc
--   sockets=x11;wayland;pulseaudio;pcsc;cups
--   devices=all
--   filesystems=home;xdg-download;xdg-documents
--
--   [Session Bus Policy]
--   org.gnome.SessionManager=talk
--   ...
--
-- The `[Context]` directives are Flatpak's analogue of:
--   * macOS NSUsageDescription keys (iter 127)
--   * Snap plugs (iter 131)
--   * Windows MSIX <Capabilities> (future iter)
--
-- The Flatpak sandbox (bubblewrap-based) enforces these
-- declarations: an app without `devices=all` cannot read
-- /dev/video0; an app without `filesystems=home` cannot
-- read $HOME. So per-permission booleans are compliance-grade
-- DP/DS signals.
--
-- The AppStream metainfo.xml provides licence-inventory
-- fields: <name>, <summary>, <description>, <url type="homepage">,
-- <project_license>, <releases><release date="...">, etc.
--
-- **The Flatpak cross-distro app layer.** Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file
--   - iter 122 winsamexports        SAM tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist
--   - iter 128 linuxdpkginventory   Debian dpkg
--   - iter 129 linuxrpminventory    RHEL/Fedora rpm
--   - iter 130 macoshomebrew        macOS Homebrew
--   - iter 131 linuxsnap            Linux Snap (sister format)
--
-- Per file the audit captures:
--   * app_id (reverse-DNS) + publisher (extracted from id)
--   * display name + summary + license + homepage + version
--   * runtime declaration
--   * per-Context permission flags (sockets/devices/filesystems/
--     shared) — direct DP/DS surface
--   * DP/DS classification from permissions + name catalogue
--
-- Why has_host_filesystem matters:
-- `filesystems=host` grants the sandbox full read access to /,
-- bypassing the bubblewrap isolation almost entirely. Track
-- this as a supply-chain risk equivalent to Snap classic
-- confinement (iter 131).
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Flatpak Sandbox            bubblewrap permission model
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (filesystems=host)
--   CWE-200, CWE-359, CWE-732, CWE-269 (sandbox bypass)
--
-- Headline finding shapes:
--   has_x11_socket             — X11 (key-logger surface).
--   has_wayland_socket         — Wayland (modern compositor).
--   has_pulseaudio_socket      — audio access (microphone).
--   has_camera_device          — `devices=all` or camera-specific.
--   has_network_shared         — network share declared.
--   has_home_filesystem        — $HOME read access.
--   has_host_filesystem        — full / read access (supply-chain
--                                risk).
--   has_recent_install         — file mtime within 30d.
--   is_pii_handling            — permissions OR name catalogue.
--   is_credential_exposure_risk — readable + app_id + PII.

CREATE TABLE IF NOT EXISTS host_linux_flatpak (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN (
            'flatpak-metadata','flatpak-metainfo-xml',
            'flatpak-appdata-xml','flatpak-desktop',
            'flatpak-repo-ref','other','unknown'
        )),
    app_id                      TEXT    NOT NULL DEFAULT '',
    publisher                   TEXT    NOT NULL DEFAULT '',
    display_name                TEXT    NOT NULL DEFAULT '',
    summary                     TEXT    NOT NULL DEFAULT '',
    homepage                    TEXT    NOT NULL DEFAULT '',
    license                     TEXT    NOT NULL DEFAULT '',
    version                     TEXT    NOT NULL DEFAULT '',
    runtime                     TEXT    NOT NULL DEFAULT '',
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_x11_socket              INTEGER NOT NULL DEFAULT 0 CHECK (has_x11_socket IN (0,1)),
    has_wayland_socket          INTEGER NOT NULL DEFAULT 0 CHECK (has_wayland_socket IN (0,1)),
    has_pulseaudio_socket       INTEGER NOT NULL DEFAULT 0 CHECK (has_pulseaudio_socket IN (0,1)),
    has_camera_device           INTEGER NOT NULL DEFAULT 0 CHECK (has_camera_device IN (0,1)),
    has_network_shared          INTEGER NOT NULL DEFAULT 0 CHECK (has_network_shared IN (0,1)),
    has_home_filesystem         INTEGER NOT NULL DEFAULT 0 CHECK (has_home_filesystem IN (0,1)),
    has_host_filesystem         INTEGER NOT NULL DEFAULT 0 CHECK (has_host_filesystem IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_flatpak_pii
    ON host_linux_flatpak(app_id) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_host_fs
    ON host_linux_flatpak(app_id) WHERE has_host_filesystem = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_camera
    ON host_linux_flatpak(app_id) WHERE has_camera_device = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_audio
    ON host_linux_flatpak(app_id) WHERE has_pulseaudio_socket = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_x11
    ON host_linux_flatpak(app_id) WHERE has_x11_socket = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_recent
    ON host_linux_flatpak(install_date_yyyymmdd, app_id) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_exposure
    ON host_linux_flatpak(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_flatpak_drift
    ON host_linux_flatpak(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_flatpak_app
    ON host_linux_flatpak(app_id, version);

CREATE INDEX IF NOT EXISTS idx_flatpak_dp_ds
    ON host_linux_flatpak(dp_ds_class, app_id);
