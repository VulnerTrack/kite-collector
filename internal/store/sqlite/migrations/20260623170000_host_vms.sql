-- 20260623170000_host_vms.sql: durable storage for per-host virtual
-- machine inventory introduced by CDMS iter 6.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_vms — one row per (asset_id, hypervisor, vm_uuid) running on
--              this host as a VM owner. Distinct from `assets` rows that
--              describe the VMs themselves: this is "what hypervisor
--              workload does this physical host run", which is the
--              required signal for CWE-1357 / RFC-3552-style capacity +
--              blast-radius analysis.
--
-- Audit value:
--   - Capacity — vcpus + ram_bytes summed per host = over-commit ratio.
--   - CWE-668 — `state='running'` VMs with snapshots from production
--     templates indicate hot-cloned environments without re-keying.
--   - CWE-693 — `state='paused'` long-lived = halted security workloads.
--   - Supply-chain — `template_id` joins to image catalog for known-bad
--     base-image vulns (cf. host_containers.image_digest).

CREATE TABLE IF NOT EXISTS host_vms (
    id              TEXT PRIMARY KEY NOT NULL,
    asset_id        TEXT NOT NULL,
    hypervisor      TEXT NOT NULL
                    CHECK (hypervisor IN (
                        'libvirt', 'hyperv', 'virtualbox',
                        'vmware', 'utm', 'parallels',
                        'multipass', 'qemu', 'unknown'
                    )),
    vm_uuid         TEXT NOT NULL,
    name            TEXT,
    state           TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (state IN (
                        'running', 'paused', 'suspended',
                        'shutdown', 'crashed', 'saved',
                        'aborted', 'shutoff', 'unknown'
                    )),
    vcpus           INTEGER,
    ram_bytes       INTEGER,
    disk_bytes      INTEGER,
    os_type         TEXT,
    template_id     TEXT,          -- when cloned from a template / OVF
    runtime_uri     TEXT,          -- "qemu:///system", "vbox", "vsphere://..."
    config_path     TEXT,          -- .xml (libvirt), .vbox (VirtualBox), .utm bundle
    started_at      TEXT,
    last_seen_at    TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    synced_at       INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_vms_unique
    ON host_vms(asset_id, hypervisor, vm_uuid);

CREATE INDEX IF NOT EXISTS idx_host_vms_unsynced
    ON host_vms(synced_at)
    WHERE synced_at IS NULL;

-- For capacity-rollup queries: "how many cores/GBs is this host hosting?"
CREATE INDEX IF NOT EXISTS idx_host_vms_running_capacity
    ON host_vms(asset_id, state, vcpus, ram_bytes)
    WHERE state = 'running';

-- For template-pinning supply-chain audits.
CREATE INDEX IF NOT EXISTS idx_host_vms_template
    ON host_vms(template_id)
    WHERE template_id IS NOT NULL;
