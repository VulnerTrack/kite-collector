-- host_win_office_c2r inventories Microsoft Office Click-
-- to-Run (C2R) artifacts cached on Windows endpoints.
--
-- C2R is the modern Office delivery channel — every Microsoft
-- 365 / Office Pro Plus / Visio / Project install on Windows
-- uses it. C2R drops rich XML manifests + per-product
-- licence files + an inventory.xml documenting the deployed
-- product matrix and channel posture:
--
--   <ODT-source>\Configuration.xml          ODT config (initial)
--   %PROGRAMDATA%\Microsoft\ClickToRun\
--           Inventory\inventory.xml          installed-product
--                                            registry
--           ProductReleases\<channel>\Office\Data\<version>\
--                                            stream metadata
--   C:\Program Files (x86)\Microsoft Office\root\Office16\
--           Licenses\<licence>.xml           per-product licence
--   C:\Program Files\Common Files\
--           Microsoft Shared\ClickToRun\
--                                            install-state
--   %APPDATA%\Microsoft\Office\Licenses\
--           <userlicense>.bin                user-cached licence
--   C:\Admin\inventory\
--           ospp_dstatus_<host>.txt          cached ospp.vbs
--                                            /dstatus output
--
-- **The Microsoft Office licence + channel layer.** Distinct
-- from:
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
--   - iter 131 linuxsnap            Snap
--   - iter 132 linuxflatpak         Flatpak
--   - iter 133 winappxmanifest      Windows MSIX
--
-- Per file the audit captures:
--   * product_id (O365ProPlusRetail / VisioPro2019Retail /
--     ProjectPro2024Volume / etc.)
--   * channel (MonthlyEnterprise / SemiAnnual / Current /
--     Beta / PerpetualVL2021 / PerpetualVL2019)
--   * office_client_edition (32 / 64)
--   * languages_count
--   * excluded_apps + excluded-app boolean flags
--   * per-product boolean flags (visio / project / access /
--     publisher / skype-for-business / lync-excluded /
--     groove-excluded)
--   * SharedComputerLicensing flag (RDS / multi-user scenarios)
--   * dp_ds_class = handles-pii (Office always handles
--     documents, email, contacts, calendar)
--
-- Why the channel matters:
--   * MonthlyEnterprise: ~1 month patch cadence
--   * SemiAnnualEnterprise: 6-month feature releases
--   * Current: consumer monthly
--   * Beta: insider preview (supply-chain risk)
--   * PerpetualVL2019/2021: no feature updates, security-only
--     until EOL (2026-10 for 2019; 2026-10 for 2021)
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Microsoft Product Terms    Office licensing
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_visio                  — Visio Pro / Visio Standard.
--   has_project                — Project Pro / Project Standard.
--   has_access                 — Microsoft Access (database).
--   has_publisher              — Microsoft Publisher.
--   has_skype_for_business     — Skype for Business client.
--   has_groove_excluded        — Groove (OneDrive sync legacy)
--                                explicitly excluded.
--   has_lync_excluded          — Lync explicitly excluded.
--   has_shared_computer_lic    — Shared Computer Licensing
--                                enabled (RDS / VDI setting).
--   is_enterprise_channel      — channel in {MonthlyEnterprise,
--                                SemiAnnualEnterprise,
--                                PerpetualVL2019/2021/2024}.
--   is_perpetual_channel       — PerpetualVL2019/2021/2024
--                                (security-only update window).
--   is_beta_channel            — Beta / Current Preview
--                                (insider; supply-chain risk).
--   has_recent_install         — file mtime within 30d.
--   is_credential_exposure_risk — readable + product_id +
--                                handles-pii (always true
--                                for Office; gated on readable
--                                + non-locked-down posture).

CREATE TABLE IF NOT EXISTS host_win_office_c2r (
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
            'c2r-configuration-xml','c2r-inventory-xml',
            'c2r-license-xml','c2r-appv-manifest',
            'ospp-dstatus-txt','user-license-bin',
            'other','unknown'
        )),
    product_id                  TEXT    NOT NULL DEFAULT '',
    channel                     TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (channel IN (
            '','monthlyenterprise','semiannualenterprise',
            'current','currentpreview','beta',
            'perpetualvl2019','perpetualvl2021',
            'perpetualvl2024','other','unknown'
        )),
    office_client_edition       TEXT    NOT NULL DEFAULT ''
        CHECK (office_client_edition IN ('','32','64')),
    languages_count             INTEGER NOT NULL DEFAULT 0,
    excluded_apps_count         INTEGER NOT NULL DEFAULT 0,
    products_count              INTEGER NOT NULL DEFAULT 0,
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'handles-pii'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    has_visio                   INTEGER NOT NULL DEFAULT 0 CHECK (has_visio IN (0,1)),
    has_project                 INTEGER NOT NULL DEFAULT 0 CHECK (has_project IN (0,1)),
    has_access                  INTEGER NOT NULL DEFAULT 0 CHECK (has_access IN (0,1)),
    has_publisher               INTEGER NOT NULL DEFAULT 0 CHECK (has_publisher IN (0,1)),
    has_skype_for_business      INTEGER NOT NULL DEFAULT 0 CHECK (has_skype_for_business IN (0,1)),
    has_groove_excluded         INTEGER NOT NULL DEFAULT 0 CHECK (has_groove_excluded IN (0,1)),
    has_lync_excluded           INTEGER NOT NULL DEFAULT 0 CHECK (has_lync_excluded IN (0,1)),
    has_shared_computer_lic     INTEGER NOT NULL DEFAULT 0 CHECK (has_shared_computer_lic IN (0,1)),
    is_enterprise_channel       INTEGER NOT NULL DEFAULT 0 CHECK (is_enterprise_channel IN (0,1)),
    is_perpetual_channel        INTEGER NOT NULL DEFAULT 0 CHECK (is_perpetual_channel IN (0,1)),
    is_beta_channel             INTEGER NOT NULL DEFAULT 0 CHECK (is_beta_channel IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 1 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_c2r_visio
    ON host_win_office_c2r(product_id) WHERE has_visio = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_project
    ON host_win_office_c2r(product_id) WHERE has_project = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_shared_lic
    ON host_win_office_c2r(product_id) WHERE has_shared_computer_lic = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_perpetual
    ON host_win_office_c2r(channel, product_id) WHERE is_perpetual_channel = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_beta
    ON host_win_office_c2r(channel, product_id) WHERE is_beta_channel = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_recent
    ON host_win_office_c2r(install_date_yyyymmdd, product_id) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_exposure
    ON host_win_office_c2r(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_c2r_drift
    ON host_win_office_c2r(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_c2r_kind
    ON host_win_office_c2r(artifact_kind, channel);

CREATE INDEX IF NOT EXISTS idx_c2r_product
    ON host_win_office_c2r(product_id, channel);
