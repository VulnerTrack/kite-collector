-- Active Directory is represented as software on domain controllers, not as
-- a standalone inventory asset. Drop the temporary logical-asset projection.
DROP VIEW IF EXISTS ad_assets;
