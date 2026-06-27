-- host_arg_tesoro inventories AR Tesoro-Nacional primary-debt-
-- issuance artifact files cached on creador-de-mercado (primary-
-- dealer) ALYC desks, BCRA-coordination officers, MECON Secretaría
-- de Finanzas debt managers, IMF-liaison and pricing-officer
-- workstations — every entity that participates in or services
-- the primary market for Tesoro debt (Letras LECAP/LECER/LEDE,
-- Bonos BONTE/BONCER/AL30/GD30/PARP/TX26).
--
-- Regulated under:
--
--   - Ley 24.156 (1992)        Administración Financiera y
--                              Sistemas de Control (LAF).
--   - Ley 27.541 (2019)        Solidaridad y Reactivación
--                              Productiva.
--   - Ley 27.605 (2020)        Sostenibilidad de Deuda Pública.
--   - Ley 27.668 (2022)        Programa de Facilidades Extendidas
--                              con el FMI (Stand-By 2022).
--   - Decreto 1344/2007        Reglamento Ley 24.156.
--   - MECON Res. 18/2017       Reglamento operativo creadores
--                              de mercado.
--   - MECON Res. 56/2022       Programa Creadores de Mercado
--                              actualizado.
--   - BCRA Com. A 7724/7726    Tesoro liquidity coordination
--                              (LELIQ-Tesoro swap rules).
--   - CNV RG 622 art.40        ALYC primary-market participation.
--   - CNV RG 731 art.7         Best execution para deuda pública.
--   - AFIP RG 4815             Exencion impuesto a la transferencia.
--   - UIF Res. 21/2018         PLA/FT para entidades financieras.
--
-- Distinct from prior iters because the shape is **primary-market
-- debt-issuance back-office** (vs secondary-market OMS):
--
--   - vs iter 200 winargsgr        — SME guarantee vs sovereign debt.
--   - vs iter 199 winargoms        — secondary-market OMS.
--   - vs iter 195 winargacdi       — custody, not issuance.
--   - vs iter 185 winargcohen      — single-ALYC, secondary.
--
-- A Tesoro artifact leak is doubly-dangerous because:
--
--   * Pre-auction bid book reveals dealer demand → reverse-engineer
--     primary-market pricing (= front-run / cornering material).
--   * Post-auction allocation reveals who got how much (= insider
--     info on dealer inventory + likely secondary supply).
--   * Programa Financiero reveals annual issuance calendar before
--     publication (= MNPI for sovereign-debt secondary market).
--   * Debt-restructuring (canje) terms reveal haircuts and timing
--     before announcement (= material non-public info, Ley 26.831
--     art.117 insider).
--   * IMF engagement documents reveal sovereign fiscal-policy
--     commitments (= sensitive bilateral material).
--   * Creador-de-mercado roster reveals primary-dealer universe
--     (= competitive intel + cyber-target list).
--   * BCRA-Tesoro coordination reveals planned LELIQ/Tesoro swaps
--     (= MNPI for ARS rates curve).
--
-- Tesoro distinctive features:
--
--   - LECAP / LECER / LEDE / LEMIN  Letras (≤ 1 año).
--   - BONTE / BONCER / BONAD        Bonos pesos / CER / dollar-linked.
--   - AL30 / AL35 / AL38 / AL41     Bonos ley argentina USD.
--   - GD29 / GD30 / GD35 / GD38 /
--     GD41 / GD46                   Bonos ley NY USD (canje 2020).
--   - PARP / DICA / DICY            Bonos par y discount legacy.
--   - TX26 / TX28 / TY27            Bonos tasa fija pesos.
--   - BOPREAL                       BCRA Bopreal (deuda comercial).
--   - Subasta competitiva           Oferta de tasa.
--   - Subasta no-competitiva        Retail price-taker.
--   - Sindicada                     Bookbuilding privado.
--   - Canje                         Debt restructuring.
--   - Recompra                      Buyback.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Tesoro\<year>\
--     auction_bid_<inst>_<yyyymmdd>.csv        oferta licitación
--     allocation_<inst>_<yyyymmdd>.csv         asignación
--     primary_dealer_roster_<yyyymm>.csv       creadores mercado
--     debt_issuance_plan_<yyyy>q<n>.pdf        Programa Financiero
--     syndicated_placement_<inst>.pdf          colocación sindicada
--     debt_restructuring_<yyyy>.pdf            canje terms
--     cnvmp_settlement_<yyyymmdd>.csv          liquidación
--     rofex_primary_<yyyymmdd>.csv             ROFEX settlement
--     financing_program_<yyyy>.pdf             Programa anual
--     bcra_coordination_<yyyymm>.pdf           Tesoro-BCRA swap
--     mecon_resolution_<n>_<yyyy>.pdf          MECON resolución
--     imf_engagement_<yyyy>.pdf                IMF facility
--     tesoro_config.ini                        app config
--
-- Regulatory base:
--
--   Ley 24.156         Administración Financiera (LAF)
--   Ley 27.541         Solidaridad y Reactivación
--   Ley 27.605         Sostenibilidad de Deuda Pública
--   Ley 27.668         Programa FMI 2022
--   Decreto 1344/2007  Reglamento LAF
--   MECON Res. 18/2017 Creadores de Mercado v1
--   MECON Res. 56/2022 Creadores de Mercado v2
--   BCRA Com. A 7724   LELIQ-Tesoro coordination
--   BCRA Com. A 7726   Tesoro liquidity rules
--   CNV RG 622 art.40  ALYC primary-market
--   CNV RG 731 art.7   Best execution deuda pública
--   AFIP RG 4815       Exenciones impuesto
--   UIF Res. 21/2018   PLA/FT
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Information Repositories (Tesoro vault)
--   T1552    Unsecured Credentials
--   T1005    Data from Local System (bid book)
--   ISO 20022  Sovereign-debt settlement standard
--   ICMA       International Capital Market Association
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_auction_bid                  — pre-auction bid book.
--   has_allocation                   — post-auction allocation.
--   has_primary_dealer_roster        — creadores mercado list.
--   has_debt_issuance_plan           — Programa Financiero.
--   has_syndicated_placement         — sindicada.
--   has_debt_restructuring           — canje terms.
--   has_cnvmp_settlement             — liquidación CNVMP.
--   has_rofex_primary                — ROFEX settlement.
--   has_financing_program            — Programa anual.
--   has_bcra_coordination            — Tesoro-BCRA swap.
--   has_mecon_resolution             — MECON resolución.
--   has_imf_engagement               — IMF facility.
--   has_dealer_cuit                  — primary-dealer CUIT.
--   has_large_bid_value              — bid > 10B ARS threshold.
--   is_credential_exposure_risk      — readable + password.
--   is_pre_auction_disclosure_risk   — readable + (auction bid OR
--                                      financing program OR
--                                      debt issuance plan).
--   is_allocation_leak_risk          — readable + (allocation OR
--                                      syndicated placement OR
--                                      CNVMP settlement).
--   is_sovereign_debt_strategy_leak  — readable + (debt restructuring
--                                      OR IMF engagement OR
--                                      BCRA coordination OR
--                                      MECON resolution).

CREATE TABLE IF NOT EXISTS host_arg_tesoro (
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
            'tesoro-auction-bid','tesoro-allocation',
            'tesoro-primary-dealer-roster','tesoro-debt-issuance-plan',
            'tesoro-syndicated-placement','tesoro-debt-restructuring',
            'tesoro-cnvmp-settlement','tesoro-rofex-primary',
            'tesoro-financing-program','tesoro-bcra-coordination',
            'tesoro-mecon-resolution','tesoro-imf-engagement',
            'tesoro-config','tesoro-credentials',
            'tesoro-installer','other','unknown'
        )),
    instrument_class            TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (instrument_class IN (
            'lecap','lecer','lede','lemin',
            'bonte','boncer','bonad',
            'al30','al35','al38','al41',
            'gd29','gd30','gd35','gd38','gd41','gd46',
            'parp','dica','dicy',
            'tx26','tx28','ty27',
            'bopreal',
            'custom','none','unknown'
        )),
    placement_method            TEXT    NOT NULL DEFAULT ''
        CHECK (placement_method IN (
            '','competitive-auction','non-competitive',
            'syndicated','private-placement',
            'swap','buyback',
            'custom','none','unknown'
        )),
    tesoro_role                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tesoro_role IN (
            'primary-dealer','finance-secretariat',
            'treasury-officer','debt-manager',
            'imf-liaison','bcra-coordinator',
            'pricing-officer','compliance-officer',
            'cco','api','other','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    dealer_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (dealer_cuit_prefix IN ('','30','33','34')),
    dealer_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    auction_id                  TEXT    NOT NULL DEFAULT '',
    bid_count                   INTEGER NOT NULL DEFAULT 0,
    allocation_count            INTEGER NOT NULL DEFAULT 0,
    dealer_count                INTEGER NOT NULL DEFAULT 0,
    largest_bid_notional_ars    INTEGER NOT NULL DEFAULT 0,
    total_offered_ars           INTEGER NOT NULL DEFAULT 0,
    total_allocated_ars         INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_auction_bid             INTEGER NOT NULL DEFAULT 0 CHECK (has_auction_bid IN (0,1)),
    has_allocation              INTEGER NOT NULL DEFAULT 0 CHECK (has_allocation IN (0,1)),
    has_primary_dealer_roster   INTEGER NOT NULL DEFAULT 0 CHECK (has_primary_dealer_roster IN (0,1)),
    has_debt_issuance_plan      INTEGER NOT NULL DEFAULT 0 CHECK (has_debt_issuance_plan IN (0,1)),
    has_syndicated_placement    INTEGER NOT NULL DEFAULT 0 CHECK (has_syndicated_placement IN (0,1)),
    has_debt_restructuring      INTEGER NOT NULL DEFAULT 0 CHECK (has_debt_restructuring IN (0,1)),
    has_cnvmp_settlement        INTEGER NOT NULL DEFAULT 0 CHECK (has_cnvmp_settlement IN (0,1)),
    has_rofex_primary           INTEGER NOT NULL DEFAULT 0 CHECK (has_rofex_primary IN (0,1)),
    has_financing_program       INTEGER NOT NULL DEFAULT 0 CHECK (has_financing_program IN (0,1)),
    has_bcra_coordination       INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_coordination IN (0,1)),
    has_mecon_resolution        INTEGER NOT NULL DEFAULT 0 CHECK (has_mecon_resolution IN (0,1)),
    has_imf_engagement          INTEGER NOT NULL DEFAULT 0 CHECK (has_imf_engagement IN (0,1)),
    has_dealer_cuit             INTEGER NOT NULL DEFAULT 0 CHECK (has_dealer_cuit IN (0,1)),
    has_large_bid_value         INTEGER NOT NULL DEFAULT 0 CHECK (has_large_bid_value IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_pre_auction_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_pre_auction_disclosure_risk IN (0,1)),
    is_allocation_leak_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_allocation_leak_risk IN (0,1)),
    is_sovereign_debt_strategy_leak INTEGER NOT NULL DEFAULT 0 CHECK (is_sovereign_debt_strategy_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_tesoro_password
    ON host_arg_tesoro(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_bid
    ON host_arg_tesoro(reporting_period, instrument_class, bid_count) WHERE has_auction_bid = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_alloc
    ON host_arg_tesoro(reporting_period, instrument_class, allocation_count) WHERE has_allocation = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_dealers
    ON host_arg_tesoro(reporting_period, dealer_count) WHERE has_primary_dealer_roster = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_plan
    ON host_arg_tesoro(reporting_period) WHERE has_debt_issuance_plan = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_sind
    ON host_arg_tesoro(reporting_period, instrument_class) WHERE has_syndicated_placement = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_restruct
    ON host_arg_tesoro(reporting_period) WHERE has_debt_restructuring = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_cnvmp
    ON host_arg_tesoro(reporting_period) WHERE has_cnvmp_settlement = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_rofex
    ON host_arg_tesoro(reporting_period) WHERE has_rofex_primary = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_prog
    ON host_arg_tesoro(reporting_period) WHERE has_financing_program = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_bcra
    ON host_arg_tesoro(reporting_period) WHERE has_bcra_coordination = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_mecon
    ON host_arg_tesoro(reporting_period) WHERE has_mecon_resolution = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_imf
    ON host_arg_tesoro(reporting_period) WHERE has_imf_engagement = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_dealer_cuit
    ON host_arg_tesoro(dealer_cuit_prefix, dealer_cuit_suffix4) WHERE has_dealer_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_large_bid
    ON host_arg_tesoro(largest_bid_notional_ars) WHERE has_large_bid_value = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_cred_exp
    ON host_arg_tesoro(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_preauction
    ON host_arg_tesoro(file_path) WHERE is_pre_auction_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_alloc_leak
    ON host_arg_tesoro(file_path) WHERE is_allocation_leak_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_strategy
    ON host_arg_tesoro(file_path) WHERE is_sovereign_debt_strategy_leak = 1;

CREATE INDEX IF NOT EXISTS idx_tesoro_drift
    ON host_arg_tesoro(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_tesoro_kind
    ON host_arg_tesoro(artifact_kind, instrument_class);
