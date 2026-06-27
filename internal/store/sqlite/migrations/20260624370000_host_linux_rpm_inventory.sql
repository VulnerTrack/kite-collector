-- host_linux_rpm_inventory inventories RPM-family Linux
-- package-manager artifacts cached on workstations.
--
-- Companion to iter 128 linuxdpkginventory (Debian/Ubuntu).
-- Together they cover RHEL, Fedora, CentOS Stream, Rocky,
-- Alma, openSUSE — ~100 % of enterprise Linux endpoints.
--
-- Files cached on workstations:
--
--   <admin-script>.rpm-qa.txt   rpm -qa --queryformat dump
--   /var/log/dnf.log            DNF transaction log
--   /var/log/dnf.rpm.log        DNF rpm-level events
--   /var/log/yum.log            legacy yum log
--   /etc/yum.repos.d/*.repo     repo definitions
--   /etc/dnf/repos.d/*.repo     newer DNF repo paths
--   /var/lib/rpm/rpmdb.sqlite   RHEL 9+ SQLite rpmdb (hash
--                                only — SQLite parsing OOS)
--   /var/lib/rpm/Packages       Berkeley DB rpmdb (hash only)
--
-- rpm-qa exports admins typically build look like:
--
--   openssl|3.0.7-26.el9|Red Hat, Inc.|https://www.openssl.org/|Cryptography toolkit
--   firefox|120.0-1.fc41|Fedora Project|https://www.mozilla.org/firefox|Mozilla Firefox
--   teams|1.6.00.21288|Microsoft Corporation|https://teams.microsoft.com|Microsoft Teams
--
-- Per pipe-delimited row we get: title (NAME), version,
-- manufacturer (VENDOR), URL, purpose (SUMMARY).
--
-- **The RPM-family package-manager metadata layer.**
-- Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file (any OS)
--   - iter 122 winsamexports        SAM-tool exports
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist
--   - iter 128 linuxdpkginventory   Debian/Ubuntu dpkg
--
-- Per file the audit captures:
--   * package count + Red Hat / Fedora / SUSE vs third-party
--     vendor split
--   * PII-package subset (catalogue shared with iters 121-128)
--   * developer-tooling presence (-devel suffix)
--   * repo count + third-party repo subset (EPEL, Microsoft,
--     Google, Oracle, Remi, RPM Fusion — supply-chain surface)
--   * install date range from DNF history
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--   Red Hat Subscription Mgmt  Software entitlements
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (third-party repo)
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_pii_packages           — packages match PII / financial /
--                                PHI catalogue.
--   has_dev_packages           — > 0 -devel packages.
--   has_third_party_repos      — > 0 repos / vendors outside
--                                Red Hat / Fedora / SUSE.
--   has_recent_install         — DNF history shows install
--                                within 30 days.
--   is_credential_exposure_risk — readable file + packages > 0 +
--                                (PII OR third-party-repos).

CREATE TABLE IF NOT EXISTS host_linux_rpm_inventory (
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
            'rpm-qa-export','dnf-history-log','dnf-rpm-log',
            'yum-log','repo-config','rpmdb-sqlite',
            'rpmdb-berkeley','other','unknown'
        )),
    package_count               INTEGER NOT NULL DEFAULT 0,
    redhat_vendor_count         INTEGER NOT NULL DEFAULT 0,
    third_party_vendor_count    INTEGER NOT NULL DEFAULT 0,
    pii_package_count           INTEGER NOT NULL DEFAULT 0,
    dev_package_count           INTEGER NOT NULL DEFAULT 0,
    repo_count                  INTEGER NOT NULL DEFAULT 0,
    third_party_repo_count      INTEGER NOT NULL DEFAULT 0,
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

CREATE INDEX IF NOT EXISTS idx_rpm_pii
    ON host_linux_rpm_inventory(package_count) WHERE has_pii_packages = 1;

CREATE INDEX IF NOT EXISTS idx_rpm_dev
    ON host_linux_rpm_inventory(artifact_kind) WHERE has_dev_packages = 1;

CREATE INDEX IF NOT EXISTS idx_rpm_thirdparty
    ON host_linux_rpm_inventory(artifact_kind) WHERE has_third_party_repos = 1;

CREATE INDEX IF NOT EXISTS idx_rpm_recent
    ON host_linux_rpm_inventory(latest_install_yyyymmdd) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_rpm_exposure
    ON host_linux_rpm_inventory(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_rpm_drift
    ON host_linux_rpm_inventory(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_rpm_kind
    ON host_linux_rpm_inventory(artifact_kind, latest_install_yyyymmdd);
