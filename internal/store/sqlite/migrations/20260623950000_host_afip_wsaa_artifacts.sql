-- host_afip_wsaa_artifacts inventories AFIP/ARCA WSAA
-- (Web-Service de Autenticación y Autorización) artifacts on
-- Argentine billing/accounting workstations. Every integration
-- that issues a `comprobante electrónico` (CAE) needs:
--   1. an X.509 cert + RSA private key issued by AFIP,
--   2. a signed TRA (Ticket de Requerimiento de Acceso) it
--      POSTs to WSAA, and
--   3. a cached TA (Ticket de Acceso) XML containing
--      `<token>` + `<sign>` valid for ~12 h.
--
-- A leaked private key gives full impersonation of the CUIT it
-- was issued to (T1552.004). A live cached `<token>` gives free
-- WSFE invoice issuance for the remainder of its TTL with no
-- additional crypto needed.
--
-- MITRE ATT&CK / CWE / Argentine context:
--   T1552.001 Credentials in Files — live <token> in TA cache
--   T1552.004 Private Keys — unencrypted .key on disk
--   T1078    Valid Accounts — CUIT impersonation
--   CWE-256, CWE-321, CWE-522, CWE-732
--   AFIP RG 2904 — facturación electrónica obligatoria
--   AFIP RG 3749 — webservice WSAA / WSFEv1
--
-- Headline finding shapes:
--   is_private_key_unencrypted     — PEM key file with no
--                                    ENCRYPTED header (T1552.004).
--   is_ta_token_present            — cached TA contains a non-
--                                    empty `<token>` element.
--   is_ta_expired                  — `<expirationTime>` is in
--                                    the past (audit-only; AFIP
--                                    re-issues these every 12 h).
--   is_world_readable / is_group_readable — POSIX perms.
--   is_credential_exposure_risk    — rollup: unencrypted key +
--                                    readable file, OR live TA
--                                    token + readable file.
--
-- The CUIT itself is NEVER stored — only the entity-type prefix
-- (20/23/24/27/30/33) and the trailing 4 digits, so the audit
-- pipeline can correlate without holding the full tax-ID.
--
-- Endpoint env (production vs homologación) is heuristic, based
-- on filename/path tokens (`produccion`/`prod` vs `homo`/`test`).

CREATE TABLE IF NOT EXISTS host_afip_wsaa_artifacts (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN ('cert','private-key','pkcs12','ta-xml','tra-cms','wsaa-config','unknown')),
    endpoint_env                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (endpoint_env IN ('production','homologation','unknown')),
    subject_cn                  TEXT    NOT NULL DEFAULT '',
    cuit_entity_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (cuit_entity_prefix IN ('','20','23','24','27','30','33','34')),
    cuit_suffix4                TEXT    NOT NULL DEFAULT '',
    ta_expires_at               TEXT    NOT NULL DEFAULT '',
    is_private_key_unencrypted  INTEGER NOT NULL DEFAULT 0 CHECK (is_private_key_unencrypted IN (0,1)),
    is_ta_token_present         INTEGER NOT NULL DEFAULT 0 CHECK (is_ta_token_present IN (0,1)),
    is_ta_expired               INTEGER NOT NULL DEFAULT 0 CHECK (is_ta_expired IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_afip_unenc_key
    ON host_afip_wsaa_artifacts(file_path) WHERE is_private_key_unencrypted = 1;

CREATE INDEX IF NOT EXISTS idx_afip_live_token
    ON host_afip_wsaa_artifacts(file_path) WHERE is_ta_token_present = 1 AND is_ta_expired = 0;

CREATE INDEX IF NOT EXISTS idx_afip_exposure
    ON host_afip_wsaa_artifacts(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_afip_drift
    ON host_afip_wsaa_artifacts(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_afip_cuit
    ON host_afip_wsaa_artifacts(cuit_entity_prefix, cuit_suffix4);
