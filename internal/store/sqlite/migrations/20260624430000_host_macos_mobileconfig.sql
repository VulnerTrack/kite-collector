-- host_macos_mobileconfig inventories macOS MDM
-- .mobileconfig configuration profiles cached on macOS
-- endpoints managed by Apple Business Manager + a third-
-- party MDM (Jamf, Microsoft Intune, Kandji, Mosyle,
-- Mosyle Manager, WorkspaceOne, etc.).
--
-- Configuration profiles are signed plist documents
-- (`.mobileconfig`) that deploy entire policy bundles:
-- WiFi credentials, VPN configs, FileVault recovery keys,
-- email accounts, certificate enrollment, app restrictions,
-- and many more. Each sub-payload is a distinct OS-enforced
-- capability.
--
-- Files cached on workstations:
--
--   /Library/Managed Preferences/<UUID>.plist
--   /var/db/ConfigurationProfiles/Setup/...
--   /var/db/ConfigurationProfiles/Store/...
--   /Library/Mobile Device Management/<Profile>.mobileconfig
--   /Library/Application Support/JAMF/...
--   /Library/Intune/...
--   /Library/Preferences/com.apple.MCX.plist
--   ~/Library/Preferences/com.apple.MCX/...
--
-- A .mobileconfig file has this top-level plist shape:
--
--   <dict>
--     <key>PayloadType</key>
--     <string>Configuration</string>
--     <key>PayloadIdentifier</key>
--     <string>com.example.corp.profile</string>
--     <key>PayloadDisplayName</key>
--     <string>Corp Standard Profile</string>
--     <key>PayloadOrganization</key>
--     <string>Acme Corp IT</string>
--     <key>PayloadUUID</key>
--     <string>...</string>
--     <key>PayloadVersion</key>
--     <integer>1</integer>
--     <key>PayloadContent</key>
--     <array>
--       <dict>
--         <key>PayloadType</key>
--         <string>com.apple.wifi.managed</string>
--         ...
--       </dict>
--       <dict>
--         <key>PayloadType</key>
--         <string>com.apple.vpn.managed</string>
--         ...
--       </dict>
--     </array>
--   </dict>
--
-- **The macOS MDM enforcement layer.** Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file
--   - iter 122 winsamexports        SAM tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist + TCC
--   - iter 128 linuxdpkginventory   Debian dpkg
--   - iter 129 linuxrpminventory    RHEL/Fedora rpm
--   - iter 130 macoshomebrew        macOS Homebrew
--   - iter 131 linuxsnap            Snap plugs
--   - iter 132 linuxflatpak         Flatpak Context
--   - iter 133 winappxmanifest      Windows MSIX Capabilities
--   - iter 134 winofficec2r         MS Office C2R
--
-- Per profile the audit captures:
--   * PayloadDisplayName + Description
--   * PayloadOrganization (the MDM authority — Jamf admin,
--     Intune tenant, Kandji org)
--   * PayloadUUID + Version
--   * Subpayloads count + per-payload-type boolean flags
--   * DP/DS classification = handles-pii (MDM controls
--     credentials, certificates, FileVault recovery keys)
--
-- Why this matters:
--   * MDM profiles are the source-of-truth for what the
--     organisation considers required on the endpoint.
--     A leaked .mobileconfig reveals the MDM tenant, the
--     deployment posture, and any embedded credentials
--     (PSK / shared secrets / certificate trust chains).
--   * Sub-payloads enumerate the org's compliance baseline:
--     "FileVault required" + "passcode complexity X" +
--     "VPN always-on" → posture footprint.
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 27001:2022 A.8.1   User endpoint devices
--   Apple Device Management    framework + Profile reference
--   GDPR Art. 32               security of processing
--   HIPAA 164.312               technical safeguards
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1601   Modify System Image / Configuration
--   T1098.004 Account Manipulation: SSH Authorized Keys
--   CWE-200, CWE-359, CWE-732, CWE-321
--
-- Headline finding shapes:
--   has_wifi_payload           — WiFi network configured
--                                (often with embedded PSK).
--   has_vpn_payload            — VPN config (with possible
--                                shared secret or cert).
--   has_certificate_payload    — cert enrollment / trust store
--                                modification.
--   has_mail_payload           — managed mail account config.
--   has_filevault_payload      — FileVault enforcement +
--                                recovery-key escrow.
--   has_passcode_payload       — passcode complexity policy.
--   has_app_restrictions       — managed app list / blocklist.
--   has_managed_apps           — managed App Store apps.
--   has_kernel_extensions      — system extension allowlist.
--   has_screensharing          — screen-sharing / remote-mgmt.
--   is_mdm_enrolled            — PayloadOrganization present
--                                = device under MDM.
--   has_recent_install         — file mtime within 30d.
--   is_pii_handling            — always handles-pii (MDM is
--                                inherently credential-bearing).
--   is_credential_exposure_risk — readable + payload_uuid +
--                                (wifi OR vpn OR certificate
--                                OR mail).

CREATE TABLE IF NOT EXISTS host_macos_mobileconfig (
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
            'mobileconfig-plist','mdm-enrollment-xml',
            'managed-preferences-plist','jamf-policy-xml',
            'intune-config-xml','other','unknown'
        )),
    payload_identifier          TEXT    NOT NULL DEFAULT '',
    payload_display_name        TEXT    NOT NULL DEFAULT '',
    payload_organization        TEXT    NOT NULL DEFAULT '',
    payload_uuid                TEXT    NOT NULL DEFAULT '',
    payload_description         TEXT    NOT NULL DEFAULT '',
    payload_version             TEXT    NOT NULL DEFAULT '',
    subpayloads_count           INTEGER NOT NULL DEFAULT 0,
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'handles-pii'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_wifi_payload            INTEGER NOT NULL DEFAULT 0 CHECK (has_wifi_payload IN (0,1)),
    has_vpn_payload             INTEGER NOT NULL DEFAULT 0 CHECK (has_vpn_payload IN (0,1)),
    has_certificate_payload     INTEGER NOT NULL DEFAULT 0 CHECK (has_certificate_payload IN (0,1)),
    has_mail_payload            INTEGER NOT NULL DEFAULT 0 CHECK (has_mail_payload IN (0,1)),
    has_filevault_payload       INTEGER NOT NULL DEFAULT 0 CHECK (has_filevault_payload IN (0,1)),
    has_passcode_payload        INTEGER NOT NULL DEFAULT 0 CHECK (has_passcode_payload IN (0,1)),
    has_app_restrictions        INTEGER NOT NULL DEFAULT 0 CHECK (has_app_restrictions IN (0,1)),
    has_managed_apps            INTEGER NOT NULL DEFAULT 0 CHECK (has_managed_apps IN (0,1)),
    has_kernel_extensions       INTEGER NOT NULL DEFAULT 0 CHECK (has_kernel_extensions IN (0,1)),
    has_screensharing           INTEGER NOT NULL DEFAULT 0 CHECK (has_screensharing IN (0,1)),
    is_mdm_enrolled             INTEGER NOT NULL DEFAULT 0 CHECK (is_mdm_enrolled IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 1 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mc_wifi
    ON host_macos_mobileconfig(payload_organization) WHERE has_wifi_payload = 1;

CREATE INDEX IF NOT EXISTS idx_mc_vpn
    ON host_macos_mobileconfig(payload_organization) WHERE has_vpn_payload = 1;

CREATE INDEX IF NOT EXISTS idx_mc_certificate
    ON host_macos_mobileconfig(payload_organization) WHERE has_certificate_payload = 1;

CREATE INDEX IF NOT EXISTS idx_mc_filevault
    ON host_macos_mobileconfig(payload_organization) WHERE has_filevault_payload = 1;

CREATE INDEX IF NOT EXISTS idx_mc_kernel_ext
    ON host_macos_mobileconfig(payload_organization) WHERE has_kernel_extensions = 1;

CREATE INDEX IF NOT EXISTS idx_mc_mdm_enrolled
    ON host_macos_mobileconfig(payload_organization, install_date_yyyymmdd) WHERE is_mdm_enrolled = 1;

CREATE INDEX IF NOT EXISTS idx_mc_recent
    ON host_macos_mobileconfig(install_date_yyyymmdd, payload_uuid) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_mc_exposure
    ON host_macos_mobileconfig(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mc_drift
    ON host_macos_mobileconfig(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mc_organization
    ON host_macos_mobileconfig(payload_organization, payload_identifier);

CREATE INDEX IF NOT EXISTS idx_mc_uuid
    ON host_macos_mobileconfig(payload_uuid);
