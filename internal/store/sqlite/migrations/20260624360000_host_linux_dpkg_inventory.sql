-- host_linux_dpkg_inventory inventories Debian/Ubuntu dpkg
-- + apt artifacts cached on Linux workstations.
--
-- Every Debian-derived system holds the canonical software
-- inventory in /var/lib/dpkg/status — one stanza per
-- installed package with the fields ISO/IEC 27001:2022 A.5.32
-- (software-licence inventory) requires:
--
--   Package          title
--   Maintainer       publisher / manufacturer
--   Version          version
--   Description      purpose
--   Homepage         vendor URL
--   Source           upstream source package
--
-- Companion artifacts:
--
--   /var/lib/dpkg/status              full package list
--   /var/lib/dpkg/info/<pkg>.copyright per-pkg licence text
--   /var/lib/dpkg/info/<pkg>.list     installed-files list
--   /var/lib/dpkg/info/<pkg>.md5sums  integrity hashes
--   /var/log/apt/history.log          install/upgrade/remove
--                                     event history with
--                                     timestamps
--   /var/log/apt/term.log             terminal output
--   /var/log/dpkg.log                 low-level dpkg actions
--
-- **The Linux-native package-manager metadata layer.**
-- Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file (any OS)
--   - iter 122 winsamexports        SAM-tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist
--
-- Per file the audit captures:
--   * package count
--   * upstream-Debian vs PPA/third-party split
--   * PII-package subset (catalogue shared with iters 121-127)
--   * developer-tooling presence (-dev/-headers packages)
--   * install date range from apt history
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Debian Policy Manual       Section 12.5 (copyright)
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (PPA detect)
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_pii_packages           — packages match PII / financial /
--                                PHI catalogue (firefox / chromium /
--                                thunderbird / libreoffice / etc.).
--   has_dev_packages           — > 0 -dev / -headers packages
--                                (workstation is a developer host).
--   has_third_party_repos      — > 0 packages with non-Debian
--                                maintainer (PPA / corporate /
--                                upstream — supply-chain surface).
--   has_recent_install         — apt history shows install/upgrade
--                                within 30d.
--   is_credential_exposure_risk — readable file + packages > 0 +
--                                (PII OR third-party-repos).

CREATE TABLE IF NOT EXISTS host_linux_dpkg_inventory (
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
            'dpkg-status','dpkg-copyright','dpkg-list',
            'apt-history-log','apt-term-log','dpkg-log',
            'deb-package-list','other','unknown'
        )),
    package_count               INTEGER NOT NULL DEFAULT 0,
    debian_maintainer_count     INTEGER NOT NULL DEFAULT 0,
    third_party_maintainer_count INTEGER NOT NULL DEFAULT 0,
    pii_package_count           INTEGER NOT NULL DEFAULT 0,
    dev_package_count           INTEGER NOT NULL DEFAULT 0,
    install_event_count         INTEGER NOT NULL DEFAULT 0,
    latest_install_yyyymmdd     TEXT    NOT NULL DEFAULT '',
    earliest_install_yyyymmdd   TEXT    NOT NULL DEFAULT '',
    has_pii_packages            INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_packages IN (0,1)),
    has_dev_packages            INTEGER NOT NULL DEFAULT 0 CHECK (has_dev_packages IN (0,1)),
    has_third_party_repos       INTEGER NOT NULL DEFAULT 0 CHECK (has_third_party_repos IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_dpkg_pii
    ON host_linux_dpkg_inventory(package_count) WHERE has_pii_packages = 1;

CREATE INDEX IF NOT EXISTS idx_dpkg_dev
    ON host_linux_dpkg_inventory(artifact_kind) WHERE has_dev_packages = 1;

CREATE INDEX IF NOT EXISTS idx_dpkg_thirdparty
    ON host_linux_dpkg_inventory(artifact_kind) WHERE has_third_party_repos = 1;

CREATE INDEX IF NOT EXISTS idx_dpkg_recent
    ON host_linux_dpkg_inventory(latest_install_yyyymmdd) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_dpkg_exposure
    ON host_linux_dpkg_inventory(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_dpkg_drift
    ON host_linux_dpkg_inventory(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_dpkg_kind
    ON host_linux_dpkg_inventory(artifact_kind, latest_install_yyyymmdd);
