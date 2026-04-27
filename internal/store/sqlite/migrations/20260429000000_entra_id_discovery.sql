-- 20260429000000_entra_id_discovery.sql: tables for the Microsoft Entra ID
-- identity discovery source (RFC-0121). Additive-only: five new tables that
-- store cloud users, service principals, groups, devices, and role assignments.
-- No existing tables are modified.

CREATE TABLE IF NOT EXISTS entra_users (
    id                        TEXT PRIMARY KEY NOT NULL,
    asset_id                  TEXT REFERENCES assets(id) ON DELETE SET NULL,
    tenant_id                 TEXT NOT NULL,
    object_id                 TEXT NOT NULL,
    user_principal_name       TEXT NOT NULL,
    display_name              TEXT,
    account_enabled           INTEGER NOT NULL DEFAULT 1,
    department                TEXT,
    job_title                 TEXT,
    mail                      TEXT,
    mfa_registered            INTEGER NOT NULL DEFAULT 0,
    mfa_methods               TEXT NOT NULL DEFAULT '[]',
    last_sign_in_datetime     INTEGER,
    last_sign_in_request_id   TEXT,
    password_policies         TEXT,
    on_premises_sync_enabled  INTEGER NOT NULL DEFAULT 0,
    on_premises_sam_account   TEXT,
    assigned_roles            TEXT NOT NULL DEFAULT '[]',
    created_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_entra_users_tenant
    ON entra_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_users_enabled
    ON entra_users(account_enabled);
CREATE INDEX IF NOT EXISTS idx_entra_users_mfa
    ON entra_users(mfa_registered);
CREATE INDEX IF NOT EXISTS idx_entra_users_last_sign_in
    ON entra_users(last_sign_in_datetime);
CREATE INDEX IF NOT EXISTS idx_entra_users_upn
    ON entra_users(user_principal_name);

CREATE TABLE IF NOT EXISTS entra_service_principals (
    id                        TEXT PRIMARY KEY NOT NULL,
    tenant_id                 TEXT NOT NULL,
    object_id                 TEXT NOT NULL,
    app_id                    TEXT NOT NULL,
    display_name              TEXT,
    service_principal_type    TEXT NOT NULL DEFAULT 'Application'
                                  CHECK(service_principal_type IN
                                        ('Application','ManagedIdentity','Legacy','SocialIdp')),
    publisher_name            TEXT,
    account_enabled           INTEGER NOT NULL DEFAULT 1,
    has_privileged_roles      INTEGER NOT NULL DEFAULT 0,
    oauth2_permission_scopes  TEXT NOT NULL DEFAULT '[]',
    app_role_assignments      TEXT NOT NULL DEFAULT '[]',
    created_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_entra_sp_tenant
    ON entra_service_principals(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_sp_privileged
    ON entra_service_principals(has_privileged_roles);
CREATE INDEX IF NOT EXISTS idx_entra_sp_type
    ON entra_service_principals(service_principal_type);

CREATE TABLE IF NOT EXISTS entra_groups (
    id                        TEXT PRIMARY KEY NOT NULL,
    tenant_id                 TEXT NOT NULL,
    object_id                 TEXT NOT NULL,
    display_name              TEXT NOT NULL,
    security_enabled          INTEGER NOT NULL DEFAULT 1,
    mail_enabled              INTEGER NOT NULL DEFAULT 0,
    group_types               TEXT NOT NULL DEFAULT '[]',
    is_role_assignable        INTEGER NOT NULL DEFAULT 0,
    membership_rule           TEXT,
    dynamic_membership        INTEGER NOT NULL DEFAULT 0,
    member_count              INTEGER,
    created_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_entra_groups_tenant
    ON entra_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_groups_role_assignable
    ON entra_groups(is_role_assignable);

CREATE TABLE IF NOT EXISTS entra_devices (
    id                        TEXT PRIMARY KEY NOT NULL,
    asset_id                  TEXT REFERENCES assets(id) ON DELETE SET NULL,
    tenant_id                 TEXT NOT NULL,
    object_id                 TEXT NOT NULL,
    device_id                 TEXT NOT NULL,
    display_name              TEXT,
    operating_system          TEXT,
    os_version                TEXT,
    trust_type                TEXT NOT NULL DEFAULT 'AzureAD'
                                  CHECK(trust_type IN ('AzureAD','ServerAD','Workplace')),
    is_compliant              INTEGER,
    is_managed                INTEGER,
    approximate_last_sign_in  INTEGER,
    registration_datetime     INTEGER,
    created_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_entra_devices_tenant
    ON entra_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_devices_compliant
    ON entra_devices(is_compliant);
CREATE INDEX IF NOT EXISTS idx_entra_devices_trust_type
    ON entra_devices(trust_type);
CREATE INDEX IF NOT EXISTS idx_entra_devices_last_sign_in
    ON entra_devices(approximate_last_sign_in);

CREATE TABLE IF NOT EXISTS entra_role_assignments (
    id                        TEXT PRIMARY KEY NOT NULL,
    tenant_id                 TEXT NOT NULL,
    principal_object_id       TEXT NOT NULL,
    principal_type            TEXT NOT NULL
                                  CHECK(principal_type IN ('user','group','servicePrincipal')),
    role_template_id          TEXT NOT NULL,
    role_display_name         TEXT NOT NULL,
    is_builtin_privileged     INTEGER NOT NULL DEFAULT 0,
    assigned_at               INTEGER,
    created_at                INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(tenant_id, principal_object_id, role_template_id)
);

CREATE INDEX IF NOT EXISTS idx_entra_roles_tenant
    ON entra_role_assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_roles_principal
    ON entra_role_assignments(principal_object_id);
CREATE INDEX IF NOT EXISTS idx_entra_roles_privileged
    ON entra_role_assignments(is_builtin_privileged);
