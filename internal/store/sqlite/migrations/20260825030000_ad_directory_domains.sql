CREATE TABLE IF NOT EXISTS ad_directory_domains (
  distinguished_name TEXT PRIMARY KEY, domain_dns_name TEXT NOT NULL,
  dns_root TEXT, netbios_name TEXT, object_sid TEXT, when_created TEXT, last_seen_at TEXT NOT NULL
);
