CREATE TABLE IF NOT EXISTS ad_directory_users (
    distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
    sam_account_name TEXT, user_principal_name TEXT, display_name TEXT, mail TEXT,
    object_sid TEXT, enabled INTEGER NOT NULL, last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ad_directory_groups (
    distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
    sam_account_name TEXT, object_sid TEXT, last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ad_directory_ous (
    distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
    name TEXT NOT NULL, gpo_links TEXT NOT NULL DEFAULT '[]', last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ad_directory_gpos (
    distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
    display_name TEXT NOT NULL, guid TEXT, version TEXT, flags TEXT, last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ad_directory_relationships (
    source_dn TEXT NOT NULL, target_dn TEXT NOT NULL, relationship_type TEXT NOT NULL,
    domain_dns_name TEXT NOT NULL, last_seen_at TEXT NOT NULL,
    PRIMARY KEY (source_dn, target_dn, relationship_type)
);
CREATE INDEX IF NOT EXISTS idx_ad_directory_relationships_target ON ad_directory_relationships(target_dn, relationship_type);
