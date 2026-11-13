-- Additive metadata: preserve old inventory rows and module versions.
ALTER TABLE installed_software ADD COLUMN source_package TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN source_version TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN package_owner TEXT NOT NULL DEFAULT 'null';
