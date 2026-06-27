-- host_macos_homebrew inventories Homebrew package manager
-- artifacts cached on macOS workstations (Apple Silicon +
-- Intel paths).
--
-- Homebrew is the de-facto macOS developer / admin package
-- manager. Per installed formula it writes:
--
--   /opt/homebrew/Cellar/<formula>/<ver>/INSTALL_RECEIPT.json
--   /opt/homebrew/Cellar/<formula>/<ver>/.brew/<formula>.rb
--   /usr/local/Cellar/<formula>/<ver>/...  (Intel)
--
-- And per installed cask (GUI app):
--
--   /opt/homebrew/Caskroom/<cask>/<ver>/.metadata/<ver>/
--           <timestamp>/Casks/<cask>.json
--   /usr/local/Caskroom/<cask>/...  (Intel)
--
-- INSTALL_RECEIPT.json carries:
--
--   homebrew_version    Brew version that installed the formula
--   time                Unix install timestamp
--   built_as_bottle     true = pre-built binary, false = source
--   poured_from_bottle  true when installed from a bottle
--   installed_as_dep    true = pulled in as runtime dep
--   installed_on_request true = explicitly `brew install <X>`
--   runtime_dependencies array of dependent formulae
--   source.spec         "stable" / "head" / "devel"
--
-- Cask JSON carries:
--
--   token               cask identifier (title slug)
--   name                display name array
--   desc                purpose / description
--   homepage            vendor URL
--   url                 download URL
--   version             version string
--   auto_updates        true = self-updating app
--
-- **The macOS-package-manager metadata layer.** Distinct from:
--   - iter 121 winsoftwarelicences  per-licence file (any OS)
--   - iter 122 winsamexports        SAM-tool aggregate
--   - iter 123 winregistryuninstall Windows Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--   - iter 126 winwingetexport      winget exports
--   - iter 127 macosinfoplist       macOS Info.plist
--   - iter 128 linuxdpkginventory   Debian dpkg
--   - iter 129 linuxrpminventory    RHEL/Fedora rpm
--
-- Per file the audit captures:
--   * formula / cask token (title)
--   * display name + description (purpose)
--   * homepage URL
--   * version + install date (from `time` Unix timestamp)
--   * installed_on_request flag (intentional install vs
--     pulled-in dependency)
--   * runtime_dependencies count
--   * is_cask flag (GUI app vs CLI tool)
--   * DP/DS classification via catalogue (firefox / chrome /
--     thunderbird / postgresql / git / openssh / etc.)
--
-- Why this is sensitive:
--   * Cask metadata reveals every GUI app installed via
--     Homebrew — Slack, Zoom, Outlook, Firefox, 1Password,
--     KeePassXC, Signal — direct PII/credential surface.
--   * Formula metadata exposes the dev-tooling profile of
--     the workstation (gh, awscli, terraform, kubectl —
--     supply-chain attack pivot points).
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain (third-party
--             tap / non-default cask)
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   is_cask                   — file describes a GUI cask
--                                (vs CLI formula).
--   has_homepage              — formula/cask ships homepage URL.
--   has_recent_install        — install_time within 30 days.
--   installed_on_request      — user explicitly installed
--                                (vs pulled in as dep).
--   is_pii_handling           — matches PII catalogue
--                                (catalogue shared with
--                                iters 121-129).
--   is_credential_exposure_risk — readable file + token +
--                                PII-handling.

CREATE TABLE IF NOT EXISTS host_macos_homebrew (
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
            'brew-install-receipt','brew-formula-rb',
            'cask-metadata-json','brewfile',
            'other','unknown'
        )),
    formula_or_token            TEXT    NOT NULL DEFAULT '',
    display_name                TEXT    NOT NULL DEFAULT '',
    description                 TEXT    NOT NULL DEFAULT '',
    homepage                    TEXT    NOT NULL DEFAULT '',
    version                     TEXT    NOT NULL DEFAULT '',
    homebrew_version            TEXT    NOT NULL DEFAULT '',
    install_time_unix           INTEGER NOT NULL DEFAULT 0,
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    runtime_deps_count          INTEGER NOT NULL DEFAULT 0,
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','handles-biometric',
            'system-utility','dev-tool','media-tool',
            'oss-no-pii','other','unknown'
        )),
    is_cask                     INTEGER NOT NULL DEFAULT 0 CHECK (is_cask IN (0,1)),
    has_homepage                INTEGER NOT NULL DEFAULT 0 CHECK (has_homepage IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    installed_on_request        INTEGER NOT NULL DEFAULT 0 CHECK (installed_on_request IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_brew_pii
    ON host_macos_homebrew(formula_or_token) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_brew_cask
    ON host_macos_homebrew(formula_or_token, version) WHERE is_cask = 1;

CREATE INDEX IF NOT EXISTS idx_brew_recent
    ON host_macos_homebrew(install_date_yyyymmdd, formula_or_token) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_brew_homepage
    ON host_macos_homebrew(formula_or_token) WHERE has_homepage = 1;

CREATE INDEX IF NOT EXISTS idx_brew_request
    ON host_macos_homebrew(formula_or_token) WHERE installed_on_request = 1;

CREATE INDEX IF NOT EXISTS idx_brew_exposure
    ON host_macos_homebrew(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_brew_drift
    ON host_macos_homebrew(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_brew_kind
    ON host_macos_homebrew(artifact_kind, install_date_yyyymmdd);

CREATE INDEX IF NOT EXISTS idx_brew_dp_ds
    ON host_macos_homebrew(dp_ds_class, formula_or_token);
