-- host_afip_dfe inventories Argentine AFIP / ARCA Domicilio
-- Fiscal Electrónico (DFE) notification cache on compliance /
-- accounting workstations.
--
-- Every contribuyente registers a DFE with AFIP/ARCA. Formal
-- tax-authority notifications arrive there:
--
--   intimación de pago               — back-tax claim
--   requerimiento de documentación   — info request
--   inicio procedimiento de
--     determinación de oficio        — AFIP audit started
--   sanción / multa                  — penalty imposed
--   ajuste impositivo                — tax determination
--   citación                         — formal summons
--
-- **Distinct enforcement channel.** Complements:
--   iter 96 PJN              — judicial notifications
--   iter 99 winargros        — UIF ROS (AML reports OUT)
--   iter 101 winbcracomunic  — BCRA regulatory advisories IN
--
-- DFE is the administrative tax-authority enforcement channel
-- IN. The presence of certain notifications (intimación de
-- pago, procedimiento de determinación, sanción) signals
-- material tax-authority exposure for the contribuyente.
--
-- Regulatory base:
--   Ley 27.430 — Reforma Tributaria
--   AFIP RG 3858/2016 — DFE obligatorio
--   AFIP RG 4280 — procedimiento determinación de oficio
--   Ley 11.683 (T.O. 1998) — Procedimiento Tributario
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 — PII (representante legal CUIT in notifications)
--
-- Headline finding shapes:
--   is_intimacion_pago        — back-tax claim issued.
--   is_audit_initiation       — procedimiento de determinación
--                                de oficio iniciado.
--   is_sancion                — sanción / multa.
--   is_pending_response       — estado=pendiente AND fecha
--                                vencimiento upcoming.
--                                Compliance-deadline alert.
--   is_overdue                — estado=vencida; default risk.
--   is_high_value             — monto > 10M ARS.
--   is_credential_exposure_risk — readable file + tax-
--                                authority enforcement PII.
--
-- Target CUIT NEVER stored verbatim — only entity-type prefix
-- + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_dfe (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    notification_kind           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (notification_kind IN (
            'intimacion-pago','requerimiento-documentacion',
            'inicio-procedimiento-doficio','sancion','multa',
            'ajuste-impositivo','comunicacion-general',
            'citacion','other','unknown'
        )),
    estado                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (estado IN (
            'pendiente','leida','contestada','vencida',
            'archivada','unknown'
        )),
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    numero_notificacion         TEXT    NOT NULL DEFAULT '',
    fecha_notificacion          TEXT    NOT NULL DEFAULT '',
    fecha_vencimiento           TEXT    NOT NULL DEFAULT '',
    monto_ars_cents             INTEGER NOT NULL DEFAULT 0,
    impuesto                    TEXT    NOT NULL DEFAULT '',
    is_intimacion_pago          INTEGER NOT NULL DEFAULT 0 CHECK (is_intimacion_pago IN (0,1)),
    is_audit_initiation         INTEGER NOT NULL DEFAULT 0 CHECK (is_audit_initiation IN (0,1)),
    is_sancion                  INTEGER NOT NULL DEFAULT 0 CHECK (is_sancion IN (0,1)),
    is_pending_response         INTEGER NOT NULL DEFAULT 0 CHECK (is_pending_response IN (0,1)),
    is_overdue                  INTEGER NOT NULL DEFAULT 0 CHECK (is_overdue IN (0,1)),
    is_high_value               INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_dfe_intimacion
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4) WHERE is_intimacion_pago = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_audit
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4) WHERE is_audit_initiation = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_sancion
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4) WHERE is_sancion = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_pending
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4) WHERE is_pending_response = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_overdue
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4) WHERE is_overdue = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_exposure
    ON host_afip_dfe(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_dfe_drift
    ON host_afip_dfe(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_dfe_entity
    ON host_afip_dfe(target_cuit_prefix, target_cuit_suffix4);
