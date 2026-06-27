-- host_arg_cohen inventories Cohen Aliados Financieros (Cohen
-- S.A.) artifact files cached on Argentine retail-and-institutional
-- ALYC client workstations.
--
-- Cohen Aliados Financieros is a top-5 Argentine ALYC (Agente de
-- Liquidación y Compensación under CNV RG 731) and FCI agent
-- through Cohen Asset Management (Cohen AM). Distinct from prior
-- AR-broker iters:
--
--   - vs iter 175 winargmercadopago    — MELI fintech (ALYC).
--   - vs iter 177 winarglemoncash      — crypto PSP.
--   - vs iter 178 winargsintesis       — FCI back-office.
--   - vs iter 165 winargib             — IB TWS/Gateway (US).
--
-- And distinct from the AR-broker collectors (winargallaria,
-- winargbalanz, winargcocoscapital, winargiolinvertironline,
-- winargmercap, winargppi, winargecotrader) because Cohen
-- uniquely combines a Cohen NetTrader desktop terminal with a
-- Cohen Asset Management FCI agent and a custom SAGGM Galileo-
-- Mariva back-office channel — none of the prior collectors
-- covers this exact triple.
--
-- Cohen distinctive features:
--
--   - Cohen NetTrader desktop terminal (.cohen / .cnt profile).
--   - Cohen Mobile OAuth2 (refresh tokens cached locally).
--   - Cohen AM FCI suscripcion / rescate / cuotaparte receipts.
--   - Cohen Equity Research PDFs (analyst reports).
--   - SAGGM Galileo / Mariva back-office channel config.
--   - Cohen Cuenta Comitente number (5-digit account ID, broker-
--     side identifier).
--   - CNV-mandated daily liquidación PDFs (CNV RG 622 art.50).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Cohen NetTrader\profile.cohen      desktop profile
--   %APPDATA%\Cohen NetTrader\session.cnt        session token
--   %APPDATA%\Cohen Mobile\oauth_token.json      mobile OAuth
--   %APPDATA%\Cohen AM\suscripcion_NN.json       FCI subscription
--   %APPDATA%\Cohen AM\cuotaparte_NN.json        cuotaparte record
--   %APPDATA%\Cohen AM\rescate_NN.json           FCI redemption
--   %APPDATA%\Cohen\liquidacion_YYYYMMDD.pdf     liquidación
--   %APPDATA%\Cohen\research\<ticker>.pdf        equity research
--   %APPDATA%\Cohen\saggm_config.ini             back-office cfg
--   %APPDATA%\Cohen\fix_session.cfg              FIX session
--   %USERPROFILE%\Documents\Cohen\               docs root
--
-- Cohen-specific risk signals:
--
--   * Cleartext password in profile.cohen = T1552 + CNV RG 1023.
--   * Cohen Mobile OAuth2 refresh token cached cleartext = T1078
--     (Valid Account — broker-side exposure to all 5 envelope
--     scopes including order placement).
--   * Cuenta Comitente number + cliente CUIT = AFIP F.8125 cross-
--     border + Bienes Personales aggregator.
--   * Cohen AM suscripcion/rescate JSON with cuotaparte_count >
--     1000 = institutional class share (CNV RG 622 art.50 +
--     FATCA / CRS reporting threshold).
--   * SAGGM Galileo/Mariva config = back-office credentials
--     (broker-wide exposure).
--   * FIX session cfg with SenderCompID = Cohen FIX adapter to
--     MAE/BYMA — exchange-side identity.
--   * Cohen Equity Research PDF count > 100 = institutional
--     research subscriber (MAR / CNV regulated under RG 622).
--   * Cliente CUIT in user record = AR resident trader (AFIP
--     F.8125 cross-border + Bienes Personales).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   CNV RG 731       Régimen de Agentes (ALYC, AAA, AAGI)
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Liquidación de operaciones
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7724 PSP custodia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP F.8125      Cross-border transfer
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales
--   Ley 27.430 art.74 FCI tax
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (OAuth refresh tokens)
--   T1059    Command and Scripting (FIX adapter)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_profile      — profile cleartext.
--   has_oauth_refresh_token      — mobile OAuth cached.
--   has_fci_subscription         — Cohen AM suscripcion.
--   has_fci_redemption           — Cohen AM rescate.
--   has_cuotaparte_record        — Cohen AM cuotaparte.
--   has_liquidacion_pdf          — daily liquidación.
--   has_research_pdf             — equity research subscription.
--   has_saggm_backoffice         — SAGGM Galileo/Mariva config.
--   has_fix_session              — FIX session cfg.
--   has_cuenta_comitente         — Cuenta Comitente number.
--   has_institutional_class      — cuotaparte > 1000.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR oauth
--                                  OR FCI receipt OR liquidacion
--                                  OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_cohen (
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
            'cohen-profile','cohen-session-token',
            'cohen-mobile-oauth',
            'cohen-fci-subscription','cohen-fci-redemption',
            'cohen-cuotaparte-record',
            'cohen-liquidacion-pdf','cohen-research-pdf',
            'cohen-saggm-config','cohen-fix-session',
            'cohen-trade-confirmation','cohen-statement',
            'cohen-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'retail-cliente','institutional-cliente',
            'fci-cuotapartista','equity-research-subscriber',
            'fix-counterparty','compliance-officer',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'ar-equity','ar-bond','ar-fci',
            'cedear','us-equity','us-bond',
            'mep-dollar','ccl-dollar',
            'multi-asset','other','unknown'
        )),
    backoffice_channel          TEXT    NOT NULL DEFAULT ''
        CHECK (backoffice_channel IN (
            '','saggm-galileo','saggm-mariva',
            'cohen-direct','sintesis','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cuenta_comitente            TEXT    NOT NULL DEFAULT '',
    oauth_token_hash            TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    fix_sender_comp_id          TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    ar_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    cedear_symbols_count        INTEGER NOT NULL DEFAULT 0,
    cuotaparte_count            INTEGER NOT NULL DEFAULT 0,
    research_pdf_count          INTEGER NOT NULL DEFAULT 0,
    liquidacion_count           INTEGER NOT NULL DEFAULT 0,
    has_password_in_profile     INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_profile IN (0,1)),
    has_oauth_refresh_token     INTEGER NOT NULL DEFAULT 0 CHECK (has_oauth_refresh_token IN (0,1)),
    has_fci_subscription        INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_subscription IN (0,1)),
    has_fci_redemption          INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_redemption IN (0,1)),
    has_cuotaparte_record       INTEGER NOT NULL DEFAULT 0 CHECK (has_cuotaparte_record IN (0,1)),
    has_liquidacion_pdf         INTEGER NOT NULL DEFAULT 0 CHECK (has_liquidacion_pdf IN (0,1)),
    has_research_pdf            INTEGER NOT NULL DEFAULT 0 CHECK (has_research_pdf IN (0,1)),
    has_saggm_backoffice        INTEGER NOT NULL DEFAULT 0 CHECK (has_saggm_backoffice IN (0,1)),
    has_fix_session             INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_session IN (0,1)),
    has_cuenta_comitente        INTEGER NOT NULL DEFAULT 0 CHECK (has_cuenta_comitente IN (0,1)),
    has_institutional_class     INTEGER NOT NULL DEFAULT 0 CHECK (has_institutional_class IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cohen_password
    ON host_arg_cohen(file_path) WHERE has_password_in_profile = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_oauth
    ON host_arg_cohen(file_path) WHERE has_oauth_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_fci_sub
    ON host_arg_cohen(cuenta_comitente, period_yyyymm) WHERE has_fci_subscription = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_fci_red
    ON host_arg_cohen(cuenta_comitente, period_yyyymm) WHERE has_fci_redemption = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_cuotaparte
    ON host_arg_cohen(cuenta_comitente, cuotaparte_count) WHERE has_cuotaparte_record = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_liquidacion
    ON host_arg_cohen(cuenta_comitente, period_yyyymm) WHERE has_liquidacion_pdf = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_research
    ON host_arg_cohen(file_path) WHERE has_research_pdf = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_saggm
    ON host_arg_cohen(backoffice_channel, period_yyyymm) WHERE has_saggm_backoffice = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_fix
    ON host_arg_cohen(fix_sender_comp_id, period_yyyymm) WHERE has_fix_session = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_institutional
    ON host_arg_cohen(cuenta_comitente, cuotaparte_count) WHERE has_institutional_class = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_cliente
    ON host_arg_cohen(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_exposure
    ON host_arg_cohen(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cohen_drift
    ON host_arg_cohen(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cohen_kind
    ON host_arg_cohen(artifact_kind, account_class);
