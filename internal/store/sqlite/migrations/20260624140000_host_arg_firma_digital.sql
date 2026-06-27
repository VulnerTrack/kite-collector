-- host_arg_firma_digital inventories Argentine ONTI-accredited
-- firma-digital certificate stores on contador / escribano /
-- abogado / sociedad workstations. Ley 25.506 makes firma
-- digital legally equivalent to a manuscript signature when
-- issued by an ONTI-accredited Certificate Authority:
--
--   AC-Modernización (AC-MOD)
--   AC-Raíz República Argentina (AC-RAÍZ)
--   AC-ONTI
--   AC-ARCA (formerly AC-AFIP)
--
-- **Distinct from iter 88 winafipwsaa** which is AFIP-WSAA-
-- specific (B2B-soap authentication, narrow path/name
-- heuristics). This collector targets general-purpose
-- document-signing certs.
--
-- Regulatory base:
--   Ley 25.506 — Firma Digital
--   Dec. 2628/2002 — reglamentación
--   ONTI Res. SDN-2017/3 — política certificación
--   AFIP RG 2238 (legacy) — política firma WSAA
--
-- MITRE / CWE:
--   T1552.004 Private Keys
--   T1078    Valid Accounts
--   CWE-321, CWE-522, CWE-732
--
-- Headline finding shapes:
--   is_expired              — today > valid_to.
--                              Hygiene-gap (cert still on disk
--                              after rotation needed).
--   is_expiring_soon        — valid_to ≤ 30 days from now.
--                              Rotation alert.
--   is_legally_binding      — ONTI-accredited issuer AND not
--                              expired. Legally equivalent to
--                              manuscript signature.
--   is_soft_cert_with_key   — PFX/P12 bundle with private key
--                              on disk (not in hardware token).
--   is_credential_exposure_risk — soft-cert-with-key + readable
--                              beyond owner = T1552.004
--                              key-theft surface.
--
-- CUIL/CUIT (when extractable from Subject DN serialNumber)
-- reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_firma_digital (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    cert_kind                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (cert_kind IN (
            'soft-cert-pfx','soft-cert-p12','x509-pem',
            'x509-der','ca-cert','key-only','other','unknown'
        )),
    issuer_ca                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (issuer_ca IN (
            'onti','ac-modernizacion','ac-raiz-republica-argentina',
            'ac-arca','ac-afip','ac-camerfirma','ac-encode',
            'other','unknown'
        )),
    subject_cn                  TEXT    NOT NULL DEFAULT '',
    subject_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (subject_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    subject_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    valid_from                  TEXT    NOT NULL DEFAULT '',
    valid_to                    TEXT    NOT NULL DEFAULT '',
    days_to_expiry              INTEGER NOT NULL DEFAULT 0,
    is_expired                  INTEGER NOT NULL DEFAULT 0 CHECK (is_expired IN (0,1)),
    is_expiring_soon            INTEGER NOT NULL DEFAULT 0 CHECK (is_expiring_soon IN (0,1)),
    is_onti_accredited          INTEGER NOT NULL DEFAULT 0 CHECK (is_onti_accredited IN (0,1)),
    is_legally_binding          INTEGER NOT NULL DEFAULT 0 CHECK (is_legally_binding IN (0,1)),
    is_soft_cert_with_key       INTEGER NOT NULL DEFAULT 0 CHECK (is_soft_cert_with_key IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_fd_expired
    ON host_arg_firma_digital(file_path) WHERE is_expired = 1;

CREATE INDEX IF NOT EXISTS idx_fd_expiring
    ON host_arg_firma_digital(valid_to) WHERE is_expiring_soon = 1;

CREATE INDEX IF NOT EXISTS idx_fd_legally_binding
    ON host_arg_firma_digital(subject_cuit_prefix, subject_cuit_suffix4) WHERE is_legally_binding = 1;

CREATE INDEX IF NOT EXISTS idx_fd_soft_with_key
    ON host_arg_firma_digital(file_path) WHERE is_soft_cert_with_key = 1;

CREATE INDEX IF NOT EXISTS idx_fd_exposure
    ON host_arg_firma_digital(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fd_drift
    ON host_arg_firma_digital(file_path, file_hash);
