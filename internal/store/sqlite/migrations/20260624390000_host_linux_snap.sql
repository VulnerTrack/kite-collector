-- host_linux_snap inventories Linux Snap package metadata
-- cached on workstations across Ubuntu, Fedora, openSUSE,
-- Manjaro, and any distro running snapd.
--
-- Snap is the dominant cross-distro app delivery format on
-- Linux. Each installed snap exposes:
--
--   /snap/<pkg>/current/meta/snap.yaml      primary metadata
--   /snap/<pkg>/current/meta/gui/*.desktop  desktop entries
--   /snap/<pkg>/current/manifest.yaml       full build manifest
--   /var/lib/snapd/seed/snaps/<pkg>.snap    seed snap blob
--   /var/lib/snapd/state.json               snapd state DB
--   ~/snap/<pkg>/current/...                per-user snap data
--
-- snap.yaml carries the ISO/IEC 27001:2022 A.5.32 inventory
-- fields directly:
--
--   name           title (e.g. firefox, slack, postgresql)
--   version        version string
--   summary        one-line purpose
--   description    long-form purpose
--   license        SPDX licence identifier
--   publisher      manufacturer (in manifest.yaml)
--   contact        support URL
--   website        vendor URL
--   base           base snap (core20 / core22 / core24)
--   confinement    strict | devmode | classic
--   type           app | gadget | kernel | base | snapd | core
--   plugs          OS-enforced capability declarations
--
-- The `plugs:` section is Snap's analogue of macOS's
-- NSUsageDescription keys (iter 127): the snapd security
-- framework will not grant the capability to a snap that
-- has not declared the corresponding plug. So the presence
-- of `camera`, `audio-record`, `home`, `personal-files`,
-- `system-files`, `network`, `removable-media` etc. plugs
-- is a compliance-grade DP/DS signal.
--
-- **The cross-distro Linux app layer.** Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file
--   - iter 122 winsamexports        SAM-tool aggregate
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist
--   - iter 128 linuxdpkginventory   Debian dpkg
--   - iter 129 linuxrpminventory    RHEL/Fedora rpm
--   - iter 130 macoshomebrew        macOS Homebrew
--
-- Per file the audit captures:
--   * name, publisher, version, summary, website, licence
--   * confinement mode + type
--   * plugs_count + per-capability boolean flags
--   * DP/DS classification from plugs + name catalogue
--
-- Why classic confinement is a security signal:
-- a `classic` snap runs unconfined with full host access,
-- bypassing the snapd security framework entirely — an
-- attacker compromising such a snap gets the host. Track
-- has_classic_confinement = 1 as a supply-chain risk.
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Snapcraft Confinement      Security model
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (classic snap)
--   CWE-200, CWE-359, CWE-732, CWE-269 (classic confinement)
--
-- Headline finding shapes:
--   has_camera_plug            — camera capability declared.
--   has_audio_plug             — audio-record / pulseaudio.
--   has_location_plug          — location-observe / location-control.
--   has_contacts_plug          — contacts-service.
--   has_home_plug              — home directory access.
--   has_personal_files_plug    — personal-files (raw fs access).
--   has_network_plug           — network capability.
--   has_classic_confinement    — full host access (supply-chain).
--   has_recent_install         — file mtime within 30d.
--   is_pii_handling            — catalogue OR plug-based PII.
--   is_credential_exposure_risk — readable + snap_name + PII.

CREATE TABLE IF NOT EXISTS host_linux_snap (
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
            'snap-yaml','snap-manifest-yaml',
            'snap-state-json','snap-seed',
            'snap-desktop-entry','other','unknown'
        )),
    snap_name                   TEXT    NOT NULL DEFAULT '',
    snap_version                TEXT    NOT NULL DEFAULT '',
    publisher                   TEXT    NOT NULL DEFAULT '',
    summary                     TEXT    NOT NULL DEFAULT '',
    website                     TEXT    NOT NULL DEFAULT '',
    license                     TEXT    NOT NULL DEFAULT '',
    base_snap                   TEXT    NOT NULL DEFAULT '',
    confinement                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (confinement IN (
            '','strict','devmode','classic','other','unknown'
        )),
    snap_type                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (snap_type IN (
            '','app','gadget','kernel','base',
            'snapd','core','other','unknown'
        )),
    plugs_count                 INTEGER NOT NULL DEFAULT 0,
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_camera_plug             INTEGER NOT NULL DEFAULT 0 CHECK (has_camera_plug IN (0,1)),
    has_audio_plug              INTEGER NOT NULL DEFAULT 0 CHECK (has_audio_plug IN (0,1)),
    has_location_plug           INTEGER NOT NULL DEFAULT 0 CHECK (has_location_plug IN (0,1)),
    has_contacts_plug           INTEGER NOT NULL DEFAULT 0 CHECK (has_contacts_plug IN (0,1)),
    has_home_plug               INTEGER NOT NULL DEFAULT 0 CHECK (has_home_plug IN (0,1)),
    has_personal_files_plug     INTEGER NOT NULL DEFAULT 0 CHECK (has_personal_files_plug IN (0,1)),
    has_network_plug            INTEGER NOT NULL DEFAULT 0 CHECK (has_network_plug IN (0,1)),
    has_classic_confinement     INTEGER NOT NULL DEFAULT 0 CHECK (has_classic_confinement IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_snap_pii
    ON host_linux_snap(snap_name) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_snap_classic
    ON host_linux_snap(snap_name) WHERE has_classic_confinement = 1;

CREATE INDEX IF NOT EXISTS idx_snap_camera
    ON host_linux_snap(snap_name) WHERE has_camera_plug = 1;

CREATE INDEX IF NOT EXISTS idx_snap_audio
    ON host_linux_snap(snap_name) WHERE has_audio_plug = 1;

CREATE INDEX IF NOT EXISTS idx_snap_location
    ON host_linux_snap(snap_name) WHERE has_location_plug = 1;

CREATE INDEX IF NOT EXISTS idx_snap_home
    ON host_linux_snap(snap_name) WHERE has_home_plug = 1;

CREATE INDEX IF NOT EXISTS idx_snap_personal_files
    ON host_linux_snap(snap_name) WHERE has_personal_files_plug = 1;

CREATE INDEX IF NOT EXISTS idx_snap_recent
    ON host_linux_snap(install_date_yyyymmdd, snap_name) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_snap_exposure
    ON host_linux_snap(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_snap_drift
    ON host_linux_snap(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_snap_name
    ON host_linux_snap(snap_name, snap_version);

CREATE INDEX IF NOT EXISTS idx_snap_dp_ds
    ON host_linux_snap(dp_ds_class, snap_name);
