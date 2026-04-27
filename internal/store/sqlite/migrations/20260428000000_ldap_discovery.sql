-- 20260428000000_ldap_discovery.sql: tables for the LDAP/Active Directory
-- discovery source (RFC-0121). Additive-only: three new tables that store
-- per-asset AD identity context, OU hierarchy, and security/distribution
-- groups. No existing tables are modified.

CREATE TABLE IF NOT EXISTS ldap_computer_accounts (
    id                   TEXT PRIMARY KEY NOT NULL,
    asset_id             TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    domain_dns_name      TEXT NOT NULL,
    domain_sid           TEXT NOT NULL,
    sam_account_name     TEXT NOT NULL,
    object_sid           TEXT NOT NULL UNIQUE,
    distinguished_name   TEXT NOT NULL,
    ou_path              TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    last_logon_timestamp INTEGER,
    password_last_set    INTEGER,
    uac_flags            INTEGER NOT NULL DEFAULT 0,
    spns                 TEXT NOT NULL DEFAULT '[]',
    member_of            TEXT NOT NULL DEFAULT '[]',
    created_at           INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at           INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_ldap_accounts_asset
    ON ldap_computer_accounts(asset_id);
CREATE INDEX IF NOT EXISTS idx_ldap_accounts_domain
    ON ldap_computer_accounts(domain_dns_name);
CREATE INDEX IF NOT EXISTS idx_ldap_accounts_enabled
    ON ldap_computer_accounts(enabled);
CREATE INDEX IF NOT EXISTS idx_ldap_accounts_last_logon
    ON ldap_computer_accounts(last_logon_timestamp);

CREATE TABLE IF NOT EXISTS ldap_organizational_units (
    id                  TEXT PRIMARY KEY NOT NULL,
    distinguished_name  TEXT NOT NULL UNIQUE,
    ou_name             TEXT NOT NULL,
    domain_dns_name     TEXT NOT NULL,
    parent_dn           TEXT,
    depth               INTEGER NOT NULL DEFAULT 1,
    description         TEXT,
    gpo_links           TEXT NOT NULL DEFAULT '[]',
    created_at          INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_ldap_ous_domain
    ON ldap_organizational_units(domain_dns_name);

CREATE TABLE IF NOT EXISTS ldap_groups (
    id                  TEXT PRIMARY KEY NOT NULL,
    distinguished_name  TEXT NOT NULL UNIQUE,
    group_name          TEXT NOT NULL,
    domain_dns_name     TEXT NOT NULL,
    group_scope         TEXT NOT NULL DEFAULT 'global'
                            CHECK(group_scope IN ('global','universal','domain_local')),
    group_type          TEXT NOT NULL DEFAULT 'security'
                            CHECK(group_type IN ('security','distribution')),
    is_privileged       INTEGER NOT NULL DEFAULT 0,
    description         TEXT,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_ldap_groups_domain
    ON ldap_groups(domain_dns_name);
CREATE INDEX IF NOT EXISTS idx_ldap_groups_privileged
    ON ldap_groups(is_privileged);
