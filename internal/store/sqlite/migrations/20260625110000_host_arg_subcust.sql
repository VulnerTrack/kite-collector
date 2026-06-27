-- host_arg_subcust inventories AR sub-custodian-for-foreign-
-- investors artifact files cached on relationship-manager,
-- fx-officer, tax-officer, settlement-officer, and proxy-officer
-- workstations at BNY-Galicia, Citibank AR, HSBC AR, Standard
-- Bank/ICBC AR, Santander AR, BBVA AR, Itaú AR, Crédit Agricole
-- AR, and JPMorgan AR — the AR banks that hold securities under
-- nominee for global custodians (BNY Mellon, Citi GCA, State
-- Street, Northern Trust, JPMorgan SS, BBH) and bridge foreign-
-- institutional-investor (FII) flows into the AR capital market
-- via Caja de Valores SA (CVSA) omnibus accounts.
--
-- Regulated under:
--
--   - CNV RG 622 art.30      Sub-custodios y custodios locales.
--   - CNV RG 622 art.36      Beneficiarios reales no-residentes.
--   - BCRA Com. A 8005       Ciberseguridad financiera (2024).
--   - BCRA Com. A 7916       Riesgo crediticio + capital.
--   - BCRA Com. A 7724       MULC (Mercado Único Libre Cambios)
--                            rules para non-resident flows.
--   - BCRA Com. A 7611       Régimen informativo no-residentes.
--   - AFIP RG 5527           Régimen no-residentes (35 % IIGG).
--   - AFIP RG 4815           Doble Gravación Tributaria (DGT).
--   - AFIP RG 830            Retenciones IIGG general.
--   - Ley 25.063 art.69-bis  Tax-exempt status for sovereign
--                            immunity (foreign central banks).
--   - Ley 26.831 art.117     Insider trading.
--   - UIF Res. 21/2018       PLA/FT para entidades financieras.
--   - UIF Res. 30-E/2017     Régimen PLA/FT no-residentes (FATCA).
--   - Ley 27.260             FATCA/CRS implementation.
--
-- Distinct from prior iters because the shape is **foreign-
-- investor-flow back-office** (FII bridge into AR markets):
--
--   - vs iter 202 winargtrustee     — bondholder trustee (creditor).
--   - vs iter 201 winargtesoro      — Tesoro primary issuance.
--   - vs iter 196 winargcrs         — CRS/FATCA reporting only.
--   - vs iter 195 winargacdi        — generic local custody.
--   - vs iter 199 winargoms         — secondary-market OMS.
--
-- A sub-custodian artifact leak is doubly-dangerous because:
--
--   * Foreign beneficial-owner roster reveals identities of FIIs
--     holding AR securities through nominee chain (= prime
--     front-running target + sovereign-immunity disclosure).
--   * MULC clearance reveals inbound/outbound FX flow timing
--     + size (= currency-trading intel + BCRA FX-stress signal).
--   * SWIFT MT540-548 settlement instructions reveal nominee
--     identities + cash settlement accounts (= SWIFT-network
--     credential reuse target).
--   * AFIP RG 5527 + IIGG non-resident filings reveal tax
--     residency declarations (= sovereign tax-treaty intelligence,
--     CRS/FATCA mapping).
--   * DGT treaty certs reveal which DGT countries' residents are
--     claiming reduced AR withholding (= tax-arbitrage map).
--   * Omnibus account reveals aggregated FII positions held under
--     single nominee (= concentration metric).
--   * ADR chain (DTC) reveals chain-of-custody for AR ADRs (YPF,
--     GGAL, BMA, BBAR, SUPV, PAM, etc.).
--   * Proxy voting record reveals FII voting intent for AGM /
--     EGM (= corporate-governance intel for tender offers).
--   * Sovereign immunity exemption reveals foreign-central-bank
--     positions (= diplomatic-sensitive financial relationship).
--
-- Sub-custodian distinctive features:
--
--   - BNY-Galicia (BNY Mellon-Banco Galicia partnership) — by
--     volume the largest FII sub-custodian in AR.
--   - Citibank AR — Citi GCA global-custodian chain.
--   - HSBC AR — HSBC Securities Services global chain.
--   - Standard Bank / ICBC AR — Asia-anchored FII flow.
--   - Santander AR / BBVA AR — Spain-anchored FII flow.
--   - Itaú AR — Brazil-anchored FII flow.
--   - Crédit Agricole AR — France-anchored FII flow.
--   - JPMorgan AR — JPMorgan SS chain.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\SubCust\<year>\
--     foreign_bo_roster_<custodian>_<yyyymm>.csv  foreign BO list
--     fx_clearance_<yyyymmdd>.csv                MULC clearance
--     withholding_cert_<country>_<yyyy>.pdf      DGT treaty cert
--     iigg_nonresident_<yyyy>q<n>.xml            AFIP 35% IIGG
--     afip_rg5527_<yyyy>q<n>.xml                 régimen no-res
--     cvsa_reconciliation_<yyyymm>.csv           CVSA reconcile
--     omnibus_account_<custodian>_<yyyymm>.csv   omnibus
--     adr_chain_<ticker>_<yyyymm>.csv            DTC chain
--     swift_instruction_<yyyymmdd>.txt           SWIFT MT54x
--     proxy_service_<ticker>_<yyyy>.pdf          proxy voting
--     corporate_action_<ticker>_<yyyymmdd>.pdf   div/coupon/split
--     sovereign_immunity_<foreign_cb>_<yyyy>.pdf sovereign exempt
--     subcust_config.ini                         app config
--
-- Regulatory base:
--
--   CNV RG 622 art.30   Sub-custodios
--   CNV RG 622 art.36   Beneficiarios reales no-residentes
--   BCRA Com. A 8005    Ciberseguridad
--   BCRA Com. A 7916    Riesgo crediticio
--   BCRA Com. A 7724    MULC rules
--   BCRA Com. A 7611    Régimen informativo no-res
--   AFIP RG 5527        Régimen no-residentes
--   AFIP RG 4815        DGT
--   AFIP RG 830         Retenciones IIGG
--   Ley 25.063 art.69-bis  Sovereign immunity
--   Ley 26.831 art.117  Insider trading
--   UIF Res. 21/2018    PLA/FT entidades financieras
--   UIF Res. 30-E/2017  PLA/FT no-residentes
--   Ley 27.260          FATCA/CRS
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (sub-cust vault)
--   T1552    Unsecured Credentials (SWIFT BIC creds)
--   T1005    Data from Local System (omnibus reconcile)
--   T1071    Application Layer Protocol (SWIFT FIN)
--   ISO 20022     Settlement message standards
--   ISO 15022     Legacy MT-class settlement
--   SWIFT FIN     MT540-548 settlement
--   SWIFT MT564   Corporate action notification
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_foreign_bo_roster            — foreign nominee list.
--   has_fx_clearance                 — MULC clearance.
--   has_withholding_cert             — DGT treaty cert.
--   has_iigg_nonresident_filing      — AFIP 35% IIGG.
--   has_afip_rg5527_filing           — régimen no-res.
--   has_cvsa_reconciliation          — CVSA reconcile.
--   has_omnibus_account              — omnibus.
--   has_adr_chain                    — DTC chain.
--   has_swift_instruction            — SWIFT MT54x.
--   has_proxy_service                — proxy voting.
--   has_corporate_action             — div/coupon/split.
--   has_sovereign_immunity           — foreign-CB exemption.
--   has_bank_cuit                    — sub-cust bank CUIT.
--   has_global_custodian             — global custodian named.
--   has_swift_bic                    — SWIFT BIC hashed.
--   has_large_omnibus_value          — omnibus > 50B ARS.
--   is_credential_exposure_risk      — readable + password OR
--                                      SWIFT BIC.
--   is_foreign_investor_pii_risk     — readable + (foreign BO OR
--                                      omnibus OR proxy OR ADR
--                                      chain).
--   is_fx_flow_intelligence_risk     — readable + (FX clearance
--                                      OR SWIFT instruction OR
--                                      corporate action).
--   is_tax_treaty_leak               — readable + (DGT cert OR
--                                      IIGG non-resident OR
--                                      AFIP RG 5527 OR
--                                      sovereign immunity).

CREATE TABLE IF NOT EXISTS host_arg_subcust (
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
            'subcust-foreign-bo-roster','subcust-fx-clearance',
            'subcust-withholding-cert','subcust-iigg-nonresident-filing',
            'subcust-afip-rg5527-filing','subcust-cvsa-reconciliation',
            'subcust-omnibus-account','subcust-adr-chain',
            'subcust-swift-instruction','subcust-proxy-service',
            'subcust-corporate-action','subcust-sovereign-immunity',
            'subcust-config','subcust-credentials',
            'subcust-installer','other','unknown'
        )),
    subcust_bank                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (subcust_bank IN (
            'bny-galicia','citibank-ar','hsbc-ar',
            'standard-bank','santander-ar','bbva-ar',
            'itau-ar','credit-agricole-ar','jpmorgan-ar',
            'custom','none','unknown'
        )),
    global_custodian            TEXT    NOT NULL DEFAULT ''
        CHECK (global_custodian IN (
            '','bny-mellon','citi-gca','hsbc-ss',
            'jpmorgan-ss','state-street','northern-trust',
            'brown-brothers-harriman','ssga','caja-de-valores',
            'custom','none','unknown'
        )),
    subcust_role                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (subcust_role IN (
            'relationship-manager','fx-officer','tax-officer',
            'settlement-officer','proxy-officer',
            'compliance-officer','back-office','middle-office',
            'cco','api','other','unknown'
        )),
    dgt_treaty_country          TEXT    NOT NULL DEFAULT ''
        CHECK (dgt_treaty_country IN (
            '','usa','spain','chile','brazil','germany',
            'uk','canada','italy','france','netherlands',
            'switzerland','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    subcust_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (subcust_cuit_prefix IN ('','30','33','34')),
    subcust_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    foreign_tin_country         TEXT    NOT NULL DEFAULT ''
        CHECK (length(foreign_tin_country) <= 4),
    foreign_tin_suffix4         TEXT    NOT NULL DEFAULT '',
    swift_bic_hash              TEXT    NOT NULL DEFAULT '',
    omnibus_account_hash        TEXT    NOT NULL DEFAULT '',
    foreign_bo_count            INTEGER NOT NULL DEFAULT 0,
    omnibus_account_count       INTEGER NOT NULL DEFAULT 0,
    omnibus_value_ars           INTEGER NOT NULL DEFAULT 0,
    fx_clearance_amount_usd     INTEGER NOT NULL DEFAULT 0,
    withholding_amount_ars      INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_foreign_bo_roster       INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_bo_roster IN (0,1)),
    has_fx_clearance            INTEGER NOT NULL DEFAULT 0 CHECK (has_fx_clearance IN (0,1)),
    has_withholding_cert        INTEGER NOT NULL DEFAULT 0 CHECK (has_withholding_cert IN (0,1)),
    has_iigg_nonresident_filing INTEGER NOT NULL DEFAULT 0 CHECK (has_iigg_nonresident_filing IN (0,1)),
    has_afip_rg5527_filing      INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_rg5527_filing IN (0,1)),
    has_cvsa_reconciliation     INTEGER NOT NULL DEFAULT 0 CHECK (has_cvsa_reconciliation IN (0,1)),
    has_omnibus_account         INTEGER NOT NULL DEFAULT 0 CHECK (has_omnibus_account IN (0,1)),
    has_adr_chain               INTEGER NOT NULL DEFAULT 0 CHECK (has_adr_chain IN (0,1)),
    has_swift_instruction       INTEGER NOT NULL DEFAULT 0 CHECK (has_swift_instruction IN (0,1)),
    has_proxy_service           INTEGER NOT NULL DEFAULT 0 CHECK (has_proxy_service IN (0,1)),
    has_corporate_action        INTEGER NOT NULL DEFAULT 0 CHECK (has_corporate_action IN (0,1)),
    has_sovereign_immunity      INTEGER NOT NULL DEFAULT 0 CHECK (has_sovereign_immunity IN (0,1)),
    has_bank_cuit               INTEGER NOT NULL DEFAULT 0 CHECK (has_bank_cuit IN (0,1)),
    has_global_custodian        INTEGER NOT NULL DEFAULT 0 CHECK (has_global_custodian IN (0,1)),
    has_swift_bic               INTEGER NOT NULL DEFAULT 0 CHECK (has_swift_bic IN (0,1)),
    has_large_omnibus_value     INTEGER NOT NULL DEFAULT 0 CHECK (has_large_omnibus_value IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_foreign_investor_pii_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_foreign_investor_pii_risk IN (0,1)),
    is_fx_flow_intelligence_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_fx_flow_intelligence_risk IN (0,1)),
    is_tax_treaty_leak          INTEGER NOT NULL DEFAULT 0 CHECK (is_tax_treaty_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_subcust_password
    ON host_arg_subcust(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_bo
    ON host_arg_subcust(reporting_period, foreign_bo_count) WHERE has_foreign_bo_roster = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_fx
    ON host_arg_subcust(reporting_period, fx_clearance_amount_usd) WHERE has_fx_clearance = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_wh
    ON host_arg_subcust(reporting_period, dgt_treaty_country) WHERE has_withholding_cert = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_iigg
    ON host_arg_subcust(reporting_period) WHERE has_iigg_nonresident_filing = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_rg5527
    ON host_arg_subcust(reporting_period) WHERE has_afip_rg5527_filing = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_cvsa
    ON host_arg_subcust(reporting_period) WHERE has_cvsa_reconciliation = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_omnibus
    ON host_arg_subcust(reporting_period, omnibus_value_ars) WHERE has_omnibus_account = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_adr
    ON host_arg_subcust(reporting_period) WHERE has_adr_chain = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_swift
    ON host_arg_subcust(swift_bic_hash) WHERE has_swift_instruction = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_proxy
    ON host_arg_subcust(reporting_period) WHERE has_proxy_service = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_ca
    ON host_arg_subcust(reporting_period) WHERE has_corporate_action = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_sovereign
    ON host_arg_subcust(reporting_period) WHERE has_sovereign_immunity = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_bank_cuit
    ON host_arg_subcust(subcust_cuit_prefix, subcust_cuit_suffix4) WHERE has_bank_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_global_cust
    ON host_arg_subcust(global_custodian) WHERE has_global_custodian = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_swift_bic
    ON host_arg_subcust(swift_bic_hash) WHERE has_swift_bic = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_large_omni
    ON host_arg_subcust(omnibus_value_ars) WHERE has_large_omnibus_value = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_cred_exp
    ON host_arg_subcust(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_fii_pii
    ON host_arg_subcust(file_path) WHERE is_foreign_investor_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_fx_intel
    ON host_arg_subcust(file_path) WHERE is_fx_flow_intelligence_risk = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_tax_treaty
    ON host_arg_subcust(file_path) WHERE is_tax_treaty_leak = 1;

CREATE INDEX IF NOT EXISTS idx_subcust_drift
    ON host_arg_subcust(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_subcust_kind
    ON host_arg_subcust(artifact_kind, subcust_bank);
