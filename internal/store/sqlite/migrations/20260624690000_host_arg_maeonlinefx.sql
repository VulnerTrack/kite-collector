-- host_arg_maeonlinefx inventories MAE OnlineFX OTC FX-trading
-- artifact files cached on Argentine bank, ALYC, fintech,
-- crypto-exchange, importer-exporter, and BCRA workstations.
--
-- MAE OnlineFX is the OTC FX trading platform on the MAE
-- (Mercado Abierto Electrónico). It is the *FX trading* leg
-- of MAE — distinct from MAEclear (OTC bond clearing) and
-- SIOPEL (OTC bond trading terminal).
--
-- MAE OnlineFX product surface:
--
--   USD/ARS Spot         dolar mayorista (interbank)
--   USD/ARS Forward      bilateral fwd contracts
--   USD/ARS NDF          non-deliverable forwards
--   EUR/ARS Spot         euro mayorista
--   BRL/ARS Spot         cross-border with Brazil
--   USDT/ARS             regulated crypto-FX (BCRA-PSAV)
--
-- **The OTC FX trading layer.** Distinct from:
--   - iter 157 winargmaeclear    MAE OTC bond clearing
--   - iter 136 winargsiopel      SIOPEL OTC bond terminal
--   - iter 139 winargprimary     Primary REST/WS futures
--   - iter 100 winargbcraforex   BCRA forex regulator side
--   - iter 158 winargprismaweb   BYMA equity clearing
--   - iter 156 winargbymadata    BYMA market-data feed
--
-- Participant classes:
--   bank                commercial bank (BCRA-authorized)
--   alyc                broker-dealer (CCL/MEP arbitrage)
--   cripto-exchange     PSAV (USDT/ARS via BCRA Com. A 7975)
--   importer-exporter   commercial FX (BCRA Com. A 7916 caps)
--   fci-manager         FCI USD position hedging
--   bcra                central bank (regulator + counterparty)
--
-- Workstation cache footprint:
--
--   C:\MAE\OnlineFX\config.xml         terminal cfg
--   C:\MAE\OnlineFX\quotes_<dt>.json   FX quotes cache
--   C:\MAE\OnlineFX\blotter_<dt>.csv   trade blotter
--   C:\MAE\OnlineFX\fwd_book_<dt>.csv  forward book
--   C:\MAE\OnlineFX\ndf_book_<dt>.csv  NDF book
--   C:\MAE\OnlineFX\usdt_book_<dt>.csv USDT/ARS book
--   C:\MAE\OnlineFX\drop_copy.fix      FIX drop-copy
--   C:\MAE\OnlineFX\session_<dt>.log   terminal session log
--
-- MAE-OnlineFX-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * USD/ARS Forward / NDF trading = BCRA Com. A 7916 scrutiny
--     (capital flight / cross-border indirect exposure)
--   * USDT/ARS trading = AFIP RG 5527 reporting tap
--   * BRL/ARS = Brazil cross-border (BCRA Com. A 7916 art. 12)
--   * Transaction > BCRA Com. A 7916 individual cap
--     (USD 200 K / month natural-person)
--   * FIX drop-copy = institutional / bank tier
--   * Cliente CUIT + USD amount = Ley 25.326 + dolar oficial
--     vs. paralelo arbitrage signal
--
-- Regulatory base:
--   Ley 26.831         Mercado de Capitales
--   BCRA Com. A 7916   Operaciones cambiarias (caps + restrictions)
--   BCRA Com. A 7724   Letras Liquidación
--   BCRA Com. A 7975   PSAV (crypto) regulation
--   BCRA Com. A 8005   Letras Tesoro
--   CNV RG 622 art.50  Operativa con divisas
--   CNV RG 731         Régimen de Agentes (FX subset)
--   CNV RG 1023        Ciberresiliencia
--   AFIP RG 5193       Securities tax reporting
--   AFIP RG 5527       Crypto tax reporting
--   Ley 25.326         Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (FIX drop-copy)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config       — terminal cleartext.
--   has_fix_drop_copy            — FIX drop-copy session.
--   has_usd_ars_spot             — dolar mayorista trades.
--   has_usd_ars_forward          — fwd contracts (BCRA scrutiny).
--   has_usd_ars_ndf              — NDF (capital flight signal).
--   has_usdt_ars_trading         — USDT/ARS (RG 5527 tap).
--   has_brl_ars_trading          — Brazil cross-border.
--   has_eur_ars_trading          — Euro mayorista.
--   has_high_volume_fx           — > USD 1 M daily volume.
--   has_bcra_above_cap           — > USD 200 K individual cap.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_maeonlinefx (
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
            'mae-onlinefx-config','mae-onlinefx-credentials',
            'mae-onlinefx-quotes-cache','mae-onlinefx-trade-blotter',
            'mae-onlinefx-forward-book','mae-onlinefx-ndf-book',
            'mae-onlinefx-usdt-book','mae-onlinefx-session-log',
            'mae-onlinefx-fix-drop-copy','mae-onlinefx-installer',
            'other','unknown'
        )),
    participant_class           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (participant_class IN (
            'bank','alyc','cripto-exchange',
            'importer-exporter','fci-manager','bcra',
            'auditor','demo','other','unknown'
        )),
    participant_id              TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    fix_session_sender          TEXT    NOT NULL DEFAULT '',
    fix_session_target          TEXT    NOT NULL DEFAULT '',
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    spot_trade_count            INTEGER NOT NULL DEFAULT 0,
    forward_trade_count         INTEGER NOT NULL DEFAULT 0,
    ndf_trade_count             INTEGER NOT NULL DEFAULT 0,
    usdt_trade_count            INTEGER NOT NULL DEFAULT 0,
    brl_trade_count             INTEGER NOT NULL DEFAULT 0,
    eur_trade_count             INTEGER NOT NULL DEFAULT 0,
    total_volume_usd_cents      INTEGER NOT NULL DEFAULT 0,
    above_cap_count             INTEGER NOT NULL DEFAULT 0,
    distinct_counterparty_count INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_fix_drop_copy           INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_drop_copy IN (0,1)),
    has_usd_ars_spot            INTEGER NOT NULL DEFAULT 0 CHECK (has_usd_ars_spot IN (0,1)),
    has_usd_ars_forward         INTEGER NOT NULL DEFAULT 0 CHECK (has_usd_ars_forward IN (0,1)),
    has_usd_ars_ndf             INTEGER NOT NULL DEFAULT 0 CHECK (has_usd_ars_ndf IN (0,1)),
    has_usdt_ars_trading        INTEGER NOT NULL DEFAULT 0 CHECK (has_usdt_ars_trading IN (0,1)),
    has_brl_ars_trading         INTEGER NOT NULL DEFAULT 0 CHECK (has_brl_ars_trading IN (0,1)),
    has_eur_ars_trading         INTEGER NOT NULL DEFAULT 0 CHECK (has_eur_ars_trading IN (0,1)),
    has_high_volume_fx          INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_fx IN (0,1)),
    has_bcra_above_cap          INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_above_cap IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_password
    ON host_arg_maeonlinefx(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_drop_copy
    ON host_arg_maeonlinefx(fix_session_sender, fix_session_target) WHERE has_fix_drop_copy = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_spot
    ON host_arg_maeonlinefx(participant_id, period_yyyymm) WHERE has_usd_ars_spot = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_forward
    ON host_arg_maeonlinefx(participant_id, period_yyyymm) WHERE has_usd_ars_forward = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_ndf
    ON host_arg_maeonlinefx(participant_id, period_yyyymm) WHERE has_usd_ars_ndf = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_usdt
    ON host_arg_maeonlinefx(participant_id, period_yyyymm) WHERE has_usdt_ars_trading = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_brl
    ON host_arg_maeonlinefx(participant_id, period_yyyymm) WHERE has_brl_ars_trading = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_volume
    ON host_arg_maeonlinefx(participant_id, total_volume_usd_cents) WHERE has_high_volume_fx = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_above_cap
    ON host_arg_maeonlinefx(participant_id, period_yyyymm, above_cap_count) WHERE has_bcra_above_cap = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_cliente
    ON host_arg_maeonlinefx(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_exposure
    ON host_arg_maeonlinefx(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_drift
    ON host_arg_maeonlinefx(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_maeonlinefx_kind
    ON host_arg_maeonlinefx(artifact_kind, participant_class);
