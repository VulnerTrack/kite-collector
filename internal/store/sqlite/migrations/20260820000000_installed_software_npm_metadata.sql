-- Richer package metadata for filesystem-scanned software (npm node_modules
-- scanner → osquery npm_packages parity). All columns are optional with safe
-- defaults, so existing rows and every other package-manager collector are
-- unaffected. install_path also makes multiple installs of the same
-- (name, version) distinct rows.
ALTER TABLE installed_software ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN license TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN homepage TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN install_path TEXT NOT NULL DEFAULT '';
ALTER TABLE installed_software ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;
