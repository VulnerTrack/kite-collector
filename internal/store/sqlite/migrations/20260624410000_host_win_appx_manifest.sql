-- host_win_appx_manifest inventories Windows MSIX/AppX
-- manifests cached on Windows workstations.
--
-- MSIX is the modern Windows packaging format. Every
-- Microsoft Store app, sideloaded MSIX, and system-shipped
-- UWP app (Calculator, Edge, Photos, Notepad, etc.) ships:
--
--   C:\Program Files\WindowsApps\<Package_x.y.z_arch_h>\
--           AppxManifest.xml      primary manifest
--           AppxBlockMap.xml      content hash map
--           AppxSignature.p7x     PKCS#7 signature
--           AppxMetadata\         metadata directory
--   %LOCALAPPDATA%\Packages\<Package>\LocalState\
--                                 per-user copy
--   %LOCALAPPDATA%\Packages\<Package>\AC\         AppContainer
--
-- AppxManifest.xml carries the ISO/IEC 27001:2022 A.5.32
-- inventory fields directly via:
--
--   <Identity Name="..." Publisher="CN=..." Version="..."/>
--   <Properties>
--     <DisplayName>...</DisplayName>
--     <PublisherDisplayName>...</PublisherDisplayName>
--     <Description>...</Description>
--     <Logo>Assets/StoreLogo.png</Logo>
--   </Properties>
--
-- And the OS-enforced DP/DS surface via the <Capabilities>
-- block. This is the Windows analogue of:
--   * macOS NSUsageDescription keys (iter 127)
--   * Linux Snap plugs (iter 131)
--   * Linux Flatpak [Context] (iter 132)
--
-- Windows enforces capabilities at the AppContainer / kernel
-- level. An MSIX app cannot access webcam / microphone /
-- location / contacts / photos unless its manifest declares
-- the corresponding <DeviceCapability> or <Capability>
-- element. So per-capability booleans are compliance-grade
-- DP/DS signals — a `webcam` declaration is a guarantee the
-- app can read camera input.
--
-- **The Windows MSIX manifest layer.** Closes the privacy-
-- capability quartet alongside iter 127 (macOS),
-- iter 131 (Snap), and iter 132 (Flatpak). Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file
--   - iter 122 winsamexports        SAM tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 128 linuxdpkginventory   Debian dpkg
--   - iter 129 linuxrpminventory    RHEL/Fedora rpm
--   - iter 130 macoshomebrew        macOS Homebrew
--
-- Per file the audit captures:
--   * Identity Name + Publisher (CN-stripped)
--   * DisplayName + Description (purpose)
--   * Version, Logo path
--   * capabilities_count + per-capability boolean flags
--   * DP/DS classification from capabilities + name catalogue
--
-- Why locked-down WindowsApps still matter: the .xml files
-- are technically readable by the SYSTEM principal only, but
-- corporate SAM tooling often copies them to shared mounts
-- or admin dumps under C:\Admin\inventory\ where they become
-- readable. Track exposure as for any other manifest.
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Microsoft Store policies   capability declaration
--   Windows AppContainer       sandbox model
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (sideloaded MSIX)
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_camera_capability      — webcam declared.
--   has_microphone_capability  — microphone declared.
--   has_location_capability    — location declared.
--   has_contacts_capability    — contacts declared.
--   has_appointments_capability — appointments / calendar.
--   has_phonecall_capability   — phoneCallHistory*.
--   has_documents_lib          — documentsLibrary access.
--   has_pictures_lib           — picturesLibrary access.
--   has_videos_lib             — videosLibrary access.
--   has_music_lib              — musicLibrary access.
--   has_internet_client        — internetClient capability.
--   has_internet_server        — internetClientServer.
--   has_recent_install         — file mtime within 30d.
--   is_pii_handling            — capability OR catalogue.
--   is_credential_exposure_risk — readable + package_name +
--                                PII-handling.
--
-- Publisher field stripped to the CN= value: the full
-- distinguished name is too long for inventory rows.

CREATE TABLE IF NOT EXISTS host_win_appx_manifest (
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
            'appxmanifest-xml','appxblockmap-xml',
            'appxmetadata','appxsignature-p7x',
            'msix-installer','other','unknown'
        )),
    package_name                TEXT    NOT NULL DEFAULT '',
    package_publisher           TEXT    NOT NULL DEFAULT '',
    display_name                TEXT    NOT NULL DEFAULT '',
    publisher_display_name      TEXT    NOT NULL DEFAULT '',
    description                 TEXT    NOT NULL DEFAULT '',
    version                     TEXT    NOT NULL DEFAULT '',
    logo_path                   TEXT    NOT NULL DEFAULT '',
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    capabilities_count          INTEGER NOT NULL DEFAULT 0,
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_camera_capability       INTEGER NOT NULL DEFAULT 0 CHECK (has_camera_capability IN (0,1)),
    has_microphone_capability   INTEGER NOT NULL DEFAULT 0 CHECK (has_microphone_capability IN (0,1)),
    has_location_capability     INTEGER NOT NULL DEFAULT 0 CHECK (has_location_capability IN (0,1)),
    has_contacts_capability     INTEGER NOT NULL DEFAULT 0 CHECK (has_contacts_capability IN (0,1)),
    has_appointments_capability INTEGER NOT NULL DEFAULT 0 CHECK (has_appointments_capability IN (0,1)),
    has_phonecall_capability    INTEGER NOT NULL DEFAULT 0 CHECK (has_phonecall_capability IN (0,1)),
    has_documents_lib           INTEGER NOT NULL DEFAULT 0 CHECK (has_documents_lib IN (0,1)),
    has_pictures_lib            INTEGER NOT NULL DEFAULT 0 CHECK (has_pictures_lib IN (0,1)),
    has_videos_lib              INTEGER NOT NULL DEFAULT 0 CHECK (has_videos_lib IN (0,1)),
    has_music_lib               INTEGER NOT NULL DEFAULT 0 CHECK (has_music_lib IN (0,1)),
    has_internet_client         INTEGER NOT NULL DEFAULT 0 CHECK (has_internet_client IN (0,1)),
    has_internet_server         INTEGER NOT NULL DEFAULT 0 CHECK (has_internet_server IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_appx_pii
    ON host_win_appx_manifest(package_name) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_appx_camera
    ON host_win_appx_manifest(package_name) WHERE has_camera_capability = 1;

CREATE INDEX IF NOT EXISTS idx_appx_microphone
    ON host_win_appx_manifest(package_name) WHERE has_microphone_capability = 1;

CREATE INDEX IF NOT EXISTS idx_appx_location
    ON host_win_appx_manifest(package_name) WHERE has_location_capability = 1;

CREATE INDEX IF NOT EXISTS idx_appx_contacts
    ON host_win_appx_manifest(package_name) WHERE has_contacts_capability = 1;

CREATE INDEX IF NOT EXISTS idx_appx_phonecall
    ON host_win_appx_manifest(package_name) WHERE has_phonecall_capability = 1;

CREATE INDEX IF NOT EXISTS idx_appx_recent
    ON host_win_appx_manifest(install_date_yyyymmdd, package_name) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_appx_exposure
    ON host_win_appx_manifest(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_appx_drift
    ON host_win_appx_manifest(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_appx_package
    ON host_win_appx_manifest(package_name, version);

CREATE INDEX IF NOT EXISTS idx_appx_dp_ds
    ON host_win_appx_manifest(dp_ds_class, package_name);
