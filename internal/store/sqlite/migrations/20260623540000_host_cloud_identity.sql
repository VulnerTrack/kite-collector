-- 20260623540000_host_cloud_identity.sql: per-host cloud identity
-- probe introduced by CDMS iter 47.
--
-- Singleton table per asset. The collector probes the well-known
-- link-local metadata endpoints:
--   - AWS IMDSv2 (http://169.254.169.254/latest/...)
--   - Azure IMDS (http://169.254.169.254/metadata/instance)
--   - GCP metadata (http://metadata.google.internal/computeMetadata/v1)
--
-- The first endpoint that responds within the timeout identifies the
-- cloud. On-prem hosts return cloud_provider='none' (the link-local
-- range routes nowhere → all three probes time out fast).
--
-- Audit value:
--   - MITRE T1082 (System Information Discovery — defender side):
--     gives the SOC a reliable cross-cloud asset key for joining
--     against the cloud-provider inventory (AWS Tag-Editor, Azure
--     Resource Graph, GCP Cloud Asset Inventory).
--   - MITRE T1078.004 (Cloud Accounts): account_id /
--     subscription_id / project_id is the join key for spotting
--     hosts that drifted to a different cloud account than expected.
--   - CWE-1188 (Insecure Default Initialization): on AWS,
--     `imds_v2_required=0` means the legacy IMDSv1 path is still
--     callable — SSRF vulnerabilities in instance-hosted services
--     can leak credentials via the metadata endpoint without auth.

CREATE TABLE IF NOT EXISTS host_cloud_identity (
    id                      TEXT PRIMARY KEY NOT NULL,
    asset_id                TEXT NOT NULL,
    cloud_provider          TEXT NOT NULL
                            CHECK (cloud_provider IN (
                                'aws', 'azure', 'gcp', 'oracle',
                                'digitalocean', 'hetzner', 'linode',
                                'none', 'unknown'
                            )),
    source                  TEXT NOT NULL
                            CHECK (source IN (
                                'aws-imdsv2', 'aws-imdsv1',
                                'azure-imds',
                                'gcp-metadata',
                                'no-probe', 'unknown'
                            )),
    instance_id             TEXT,            -- "i-0abc...", VM resource ID, GCE instance ID
    account_id              TEXT,            -- AWS account, Azure subscription, GCP project
    region                  TEXT,
    availability_zone       TEXT,
    instance_type           TEXT,
    image_id                TEXT,            -- AMI / image URL / VM image
    hostname                TEXT,            -- cloud-side hostname
    resource_group          TEXT,            -- Azure only
    private_ip              TEXT,
    public_ip               TEXT,            -- when surfaced in metadata
    vpc_id                  TEXT,            -- AWS VPC ID
    vnet_id                 TEXT,            -- Azure VNet ID
    network_id              TEXT,            -- GCP network self-link
    security_groups_json    TEXT NOT NULL DEFAULT '[]',
    tags_json               TEXT NOT NULL DEFAULT '[]',
    is_spot_instance        INTEGER NOT NULL DEFAULT 0
                            CHECK (is_spot_instance IN (0, 1)),
    imds_v2_required        INTEGER NOT NULL DEFAULT 0
                            CHECK (imds_v2_required IN (0, 1)),
    raw_payload_hash        TEXT,            -- sha256 of the IMDS JSON for drift
    last_seen_at            TEXT NOT NULL,
    collected_at            TEXT NOT NULL,
    synced_at               INTEGER,
    created_at              INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One row per asset.
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_cloud_identity_asset
    ON host_cloud_identity(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_cloud_identity_unsynced
    ON host_cloud_identity(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: cross-cloud join by instance_id.
CREATE INDEX IF NOT EXISTS idx_host_cloud_identity_instance
    ON host_cloud_identity(cloud_provider, instance_id)
    WHERE instance_id IS NOT NULL;

-- Fast path: "show me hosts allowing IMDSv1" (CWE-1188).
CREATE INDEX IF NOT EXISTS idx_host_cloud_identity_imdsv1
    ON host_cloud_identity(asset_id, cloud_provider)
    WHERE cloud_provider = 'aws' AND imds_v2_required = 0;
