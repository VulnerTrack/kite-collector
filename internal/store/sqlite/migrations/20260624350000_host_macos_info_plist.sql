-- host_macos_info_plist inventories macOS .app bundle
-- Info.plist files cached on macOS workstations.
--
-- Every macOS app ships:
--
--   /Applications/<App>.app/Contents/Info.plist
--   /System/Applications/<App>.app/Contents/Info.plist
--   ~/Applications/<App>.app/Contents/Info.plist
--   /Library/Application Support/<vendor>/<app>/license.plist
--
-- The plist carries the canonical software-licence inventory
-- fields:
--
--   CFBundleIdentifier         reverse-DNS — publisher + product
--   CFBundleDisplayName        title shown to user
--   CFBundleShortVersionString version
--   CFBundleVersion            build number
--   NSHumanReadableCopyright   manufacturer / copyright owner
--   LSApplicationCategoryType  purpose (App Store category)
--
-- And the canonical DP/DS declaration set — Apple's
-- NS*UsageDescription privacy keys are mandatory under
-- macOS's TCC framework. An app cannot access protected
-- data without declaring intent in its plist:
--
--   NSCameraUsageDescription
--   NSMicrophoneUsageDescription
--   NSContactsUsageDescription
--   NSPhotoLibraryUsageDescription
--   NSCalendarsUsageDescription
--   NSRemindersUsageDescription
--   NSLocationUsageDescription
--   NSLocationWhenInUseUsageDescription
--   NSLocationAlwaysUsageDescription
--   NSHealthShareUsageDescription
--   NSHealthUpdateUsageDescription
--   NSFaceIDUsageDescription
--   NSAppleEventsUsageDescription
--   NSSystemAdministrationUsageDescription
--
-- **The macOS-native licence + privacy layer.** Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file (any OS)
--   - iter 122 winsamexports        SAM-tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--
-- Per plist the audit captures:
--   * bundle_id + publisher (extracted from reverse-DNS
--     leading domain)
--   * display_name, version, copyright, category
--   * privacy_keys_count + per-key boolean flags
--   * dp_ds_class derived from privacy keys + catalogue
--
-- Why privacy keys are the authoritative DP/DS signal on
-- macOS: TCC enforces the keys; an app missing a usage-
-- description string is *blocked* from accessing the data.
-- The presence of NSCameraUsageDescription is therefore a
-- guarantee the app reads camera input. That's a
-- compliance-grade answer to "gestiona DP/DS?".
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Apple App Store Review     Privacy-key requirements
--   GDPR Art. 13 / 14          Information to data subjects
--   Apple App Tracking         Transparency framework
--   Ley 25.326 (AR)            Protección de Datos Personales
--   HIPAA 164.308              when Health keys present
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1059.002 Command and Scripting Interpreter: AppleScript
--             (NSAppleEventsUsageDescription detect)
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_camera_access       — NSCameraUsageDescription
--   has_microphone_access   — NSMicrophoneUsageDescription
--   has_location_access     — any NSLocation* key
--   has_contacts_access     — NSContactsUsageDescription
--   has_photos_access       — NSPhotoLibraryUsageDescription
--   has_calendar_access     — NSCalendarsUsageDescription
--   has_health_access       — NSHealth* — direct HIPAA scope
--   has_faceid_access       — NSFaceIDUsageDescription —
--                              biometric PII
--   is_pii_handling         — any privacy key set OR catalogue
--                              match on bundle_id
--   is_credential_exposure_risk — readable + bundle_id +
--                              PII-handling

CREATE TABLE IF NOT EXISTS host_macos_info_plist (
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
            'app-info-plist','license-plist',
            'embedded-info-plist','other','unknown'
        )),
    bundle_id                   TEXT    NOT NULL DEFAULT '',
    publisher                   TEXT    NOT NULL DEFAULT '',
    display_name                TEXT    NOT NULL DEFAULT '',
    version                     TEXT    NOT NULL DEFAULT '',
    copyright                   TEXT    NOT NULL DEFAULT '',
    category                    TEXT    NOT NULL DEFAULT '',
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    privacy_keys_count          INTEGER NOT NULL DEFAULT 0,
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_camera_access           INTEGER NOT NULL DEFAULT 0 CHECK (has_camera_access IN (0,1)),
    has_microphone_access       INTEGER NOT NULL DEFAULT 0 CHECK (has_microphone_access IN (0,1)),
    has_location_access         INTEGER NOT NULL DEFAULT 0 CHECK (has_location_access IN (0,1)),
    has_contacts_access         INTEGER NOT NULL DEFAULT 0 CHECK (has_contacts_access IN (0,1)),
    has_photos_access           INTEGER NOT NULL DEFAULT 0 CHECK (has_photos_access IN (0,1)),
    has_calendar_access         INTEGER NOT NULL DEFAULT 0 CHECK (has_calendar_access IN (0,1)),
    has_health_access           INTEGER NOT NULL DEFAULT 0 CHECK (has_health_access IN (0,1)),
    has_faceid_access           INTEGER NOT NULL DEFAULT 0 CHECK (has_faceid_access IN (0,1)),
    has_appleevents_access      INTEGER NOT NULL DEFAULT 0 CHECK (has_appleevents_access IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_plist_pii
    ON host_macos_info_plist(bundle_id, publisher) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_plist_camera
    ON host_macos_info_plist(bundle_id) WHERE has_camera_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_microphone
    ON host_macos_info_plist(bundle_id) WHERE has_microphone_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_location
    ON host_macos_info_plist(bundle_id) WHERE has_location_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_health
    ON host_macos_info_plist(bundle_id) WHERE has_health_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_faceid
    ON host_macos_info_plist(bundle_id) WHERE has_faceid_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_appleevents
    ON host_macos_info_plist(bundle_id) WHERE has_appleevents_access = 1;

CREATE INDEX IF NOT EXISTS idx_plist_exposure
    ON host_macos_info_plist(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_plist_drift
    ON host_macos_info_plist(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_plist_bundle
    ON host_macos_info_plist(bundle_id, version);

CREATE INDEX IF NOT EXISTS idx_plist_publisher
    ON host_macos_info_plist(publisher, dp_ds_class);
