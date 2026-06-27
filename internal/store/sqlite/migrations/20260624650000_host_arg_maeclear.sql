-- host_arg_maeclear inventories MAEclear OTC clearing
-- artifact files cached on Argentine bank, ALYC, and
-- sociedad-gerente back-office workstations.
--
-- MAEclear is the central counterparty (CCP) + clearing
-- system for OTC trades on the MAE (Mercado Abierto
-- Electrónico) platform. It is the *clearing* leg of MAE
-- (distinct from SIOPEL, the OTC trading terminal).
--
-- MAEclear settles:
--
--   - Sovereign + corporate bonds (AL30/GD30/AY24/etc.)
--   - REPO / caución bilateral OTC
--   - BCRA-direct Leliq + Leliq-USD (BCRA-only counterparty)
--   - FX-forward bilateral confirms
--   - Bilateral "afirmación" workflow (T+0 confirms)
--
-- **The OTC clearing layer.** Distinct from:
--
--   - iter 136 winargsiopel        — SIOPEL trading terminal
--   - iter 137 winargcvsa          — CVSA equity custody
--   - iter 109 winargmatbarofex    — MTR-Rofex futures CCP
--   - iter 156 winargbymadata      — BYMA market-data feed
--
-- MAEclear users:
--   - Banks (commercial settlement, BCRA-direct LELIQ)
--   - ALYCs (OTC bond client orders)
--   - Sociedades Gerentes (FCI bond custody movements)
--   - BCRA (sovereign-debt primary issuance)
--
-- Workstation cache footprint:
--
--   C:\MAEclear\config\settings.xml       terminal cfg
--   C:\MAEclear\settlement\<dt>.xml       settle instructions
--   C:\MAEclear\affirmation\<dt>.log      bilateral confirms
--   C:\MAEclear\repo_book\<dt>.csv        REPO agreements
--   C:\MAEclear\leliq\<dt>.xml            BCRA Leliq settle
--   C:\MAEclear\drop_copy\<dt>.fix        FIX drop-copy
--   %APPDATA%\MAEclear\session.log        terminal session
--
-- MAEclear-specific risk signals:
--   * Settlement-failure event = T+1 fail (CNV RG 622 art. 47)
--   * REPO agreement > 30-day tenor = unusual
--   * BCRA-direct Leliq exposure = bank-only access tier
--   * Sovereign OTC AL30/GD30 = market-maker activity
--   * Cross-border FX-forward = BCRA Com. A 7916 scrutiny
--   * Cliente CUIT + ticker + amount = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 622 art.47 Liquidación T+1
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 operaciones cambiarias
--   BCRA Com. A 7724 Letras Liquidación
--   Ley 25.326       Protección de Datos Personales
--   UIF Resol. 30    PEP / AML
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (FIX drop-copy)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — terminal cleartext.
--   has_fix_drop_copy              — FIX drop-copy session.
--   has_settlement_failure         — T+1 settle fail event.
--   has_repo_activity              — REPO bilateral book.
--   has_long_tenor_repo            — REPO > 30-day tenor.
--   has_bcra_leliq_settlement      — BCRA-direct Leliq.
--   has_sovereign_otc_activity     — AL30/GD30/AY24 OTC.
--   has_cross_border_fx_forward    — USD/ARS FX-forward.
--   has_high_settlement_volume     — > 1 G ARS / day.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_maeclear (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN (
            'maeclear-config','maeclear-credentials',
            'maeclear-settlement-book','maeclear-affirmation-log',
            'maeclear-repo-book','maeclear-leliq-log',
            'maeclear-drop-copy','maeclear-session-log',
            'maeclear-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'bank','alyc','sociedad-gerente','bcra',
            'auditor','demo','other','unknown'
        )),
    participant_id              TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    fix_session_sender          TEXT    NOT NULL DEFAULT '',
    fix_session_target          TEXT    NOT NULL DEFAULT '',
    settlement_first_seen       TEXT    NOT NULL DEFAULT '',
    settlement_last_seen        TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    settlement_count            INTEGER NOT NULL DEFAULT 0,
    settlement_fail_count       INTEGER NOT NULL DEFAULT 0,
    affirmation_count           INTEGER NOT NULL DEFAULT 0,
    repo_count                  INTEGER NOT NULL DEFAULT 0,
    repo_max_tenor_days         INTEGER NOT NULL DEFAULT 0,
    leliq_settlement_count      INTEGER NOT NULL DEFAULT 0,
    sovereign_otc_count         INTEGER NOT NULL DEFAULT 0,
    fx_forward_count            INTEGER NOT NULL DEFAULT 0,
    total_volume_ars_cents      INTEGER NOT NULL DEFAULT 0,
    distinct_counterparty_count INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_fix_drop_copy           INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_drop_copy IN (0,1)),
    has_settlement_failure      INTEGER NOT NULL DEFAULT 0 CHECK (has_settlement_failure IN (0,1)),
    has_repo_activity           INTEGER NOT NULL DEFAULT 0 CHECK (has_repo_activity IN (0,1)),
    has_long_tenor_repo         INTEGER NOT NULL DEFAULT 0 CHECK (has_long_tenor_repo IN (0,1)),
    has_bcra_leliq_settlement   INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_leliq_settlement IN (0,1)),
    has_sovereign_otc_activity  INTEGER NOT NULL DEFAULT 0 CHECK (has_sovereign_otc_activity IN (0,1)),
    has_cross_border_fx_forward INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_border_fx_forward IN (0,1)),
    has_high_settlement_volume  INTEGER NOT NULL DEFAULT 0 CHECK (has_high_settlement_volume IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_maeclear_password
    ON host_arg_maeclear(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_drop_copy
    ON host_arg_maeclear(fix_session_sender, fix_session_target) WHERE has_fix_drop_copy = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_fails
    ON host_arg_maeclear(participant_id, period_yyyymm) WHERE has_settlement_failure = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_repo
    ON host_arg_maeclear(participant_id, period_yyyymm) WHERE has_repo_activity = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_long_repo
    ON host_arg_maeclear(participant_id, repo_max_tenor_days) WHERE has_long_tenor_repo = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_leliq
    ON host_arg_maeclear(participant_id, period_yyyymm) WHERE has_bcra_leliq_settlement = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_sovereign
    ON host_arg_maeclear(participant_id, period_yyyymm) WHERE has_sovereign_otc_activity = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_fx
    ON host_arg_maeclear(participant_id, period_yyyymm) WHERE has_cross_border_fx_forward = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_volume
    ON host_arg_maeclear(participant_id, total_volume_ars_cents) WHERE has_high_settlement_volume = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_cliente
    ON host_arg_maeclear(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_exposure
    ON host_arg_maeclear(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_maeclear_drift
    ON host_arg_maeclear(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_maeclear_kind
    ON host_arg_maeclear(artifact_kind, account_class);
