-- 20260623160000_host_containers.sql: durable storage for per-host
-- container inventory introduced by CDMS iter 5.
--
-- Distinct from the existing `assets` rows that the discovery/docker
-- source emits: those treat a container as a top-level asset (cross-host
-- inventory). This table is the per-host CHILD record (one row per
-- container running ON this asset), so an audit can ask "what's running
-- on host X?" without a cross-table join.
--
-- `runtime` discriminates so a single host with both Docker and Podman
-- (rootless) running the same image doesn't collide on container_id —
-- both runtimes happen to use the same hash format but originate from
-- different daemons.
--
-- Audit value:
--   - CWE-732 — `privileged=1` containers (--privileged flag)
--   - CWE-269 — containers running as root inside (root_uid=1) with
--     mounts from /etc, /var/run, /proc on the host
--   - CWE-668 — host network namespace shared (host_network=1)

CREATE TABLE IF NOT EXISTS host_containers (
    id              TEXT PRIMARY KEY NOT NULL,
    asset_id        TEXT NOT NULL,
    runtime         TEXT NOT NULL
                    CHECK (runtime IN (
                        'docker', 'podman', 'containerd',
                        'cri-o', 'lxc', 'unknown'
                    )),
    container_id    TEXT NOT NULL,
    name            TEXT,
    image           TEXT,
    image_id        TEXT,
    image_digest    TEXT,
    state           TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (state IN (
                        'created', 'running', 'paused',
                        'restarting', 'exited', 'dead', 'unknown'
                    )),
    status          TEXT,           -- free-form runtime status ("Up 2 hours")
    command         TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    exit_code       INTEGER,
    privileged      INTEGER NOT NULL DEFAULT 0
                    CHECK (privileged IN (0, 1)),
    host_network    INTEGER NOT NULL DEFAULT 0
                    CHECK (host_network IN (0, 1)),
    host_pid        INTEGER NOT NULL DEFAULT 0
                    CHECK (host_pid IN (0, 1)),
    root_uid        INTEGER,        -- 0 = running as root in container
    ports_json      TEXT,           -- [{"host_port":80,"container_port":8080,"proto":"tcp"}]
    mounts_json     TEXT,           -- [{"src":"/var/lib/x","dst":"/data","type":"bind","ro":false}]
    networks_json   TEXT,           -- ["bridge","my-overlay"]
    labels_json     TEXT,           -- {"com.example.role":"db"}
    last_seen_at    TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    synced_at       INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_containers_unique
    ON host_containers(asset_id, runtime, container_id);

CREATE INDEX IF NOT EXISTS idx_host_containers_unsynced
    ON host_containers(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-732 finding: "show me privileged containers".
CREATE INDEX IF NOT EXISTS idx_host_containers_privileged
    ON host_containers(asset_id, runtime)
    WHERE privileged = 1;

-- For supply-chain audits joining containers -> SBOM by image_digest.
CREATE INDEX IF NOT EXISTS idx_host_containers_image_digest
    ON host_containers(image_digest)
    WHERE image_digest IS NOT NULL;
