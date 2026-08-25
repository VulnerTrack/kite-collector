CREATE TABLE IF NOT EXISTS ad_directory_computers (
    distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
    name TEXT, dns_host_name TEXT, operating_system TEXT, operating_system_version TEXT,
    object_sid TEXT, enabled INTEGER NOT NULL, last_logon TEXT, password_last_set TEXT,
    service_principal_names TEXT NOT NULL DEFAULT '[]', last_seen_at TEXT NOT NULL
);
