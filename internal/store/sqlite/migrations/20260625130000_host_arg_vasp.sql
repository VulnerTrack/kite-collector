-- host_arg_vasp inventories AR Virtual-Asset-Service-Provider
-- (VASP / PSAV = Proveedor de Servicios de Activos Virtuales)
-- artifact files cached on compliance-officer, AML-officer,
-- chainalytics-analyst, treasury-officer, and security-engineer
-- workstations at Lemon Cash, Belo, Bitso AR, Ripio, Buenbit,
-- Bitnovo AR, SatoshiTango, Decrypto, Bitex, Letsbit, BUDA AR —
-- entities registered under CNV RG 1058/2024 (PSAV registry).
--
-- Regulated under:
--
--   - Ley 27.739 (Oct 2024)  AR adoption of FATF Recommendations
--                            15 + 16 (virtual assets + Travel Rule);
--                            extends UIF jurisdiction to PSAVs.
--   - Ley 27.260             FATCA / CRS integration.
--   - CNV RG 1058/2024       Registro de PSAV (Proveedor de
--                            Servicios de Activos Virtuales).
--   - CNV RG 1023            Ciberresiliencia.
--   - BCRA Com. A 8155       Crypto exposure limits for entidades
--                            financieras.
--   - BCRA Com. A 7724       MULC + cross-border crypto.
--   - UIF Res. 49/2024       PLA/FT específico PSAV.
--   - UIF Res. 21/2018       PLA/FT general entidades financieras.
--   - AFIP RG 5697           Régimen información cripto.
--   - AFIP Bienes Personales Activos virtuales (declarables).
--   - Ley 25.246             PLA/FT marco general.
--   - Ley 25.326             Datos Personales.
--   - Ley 27.401             Responsabilidad penal jurídica.
--   - Ley 26.831 art.117     Insider trading (extiende a tokens
--                            asimilables a valores negociables).
--   - FATF Recommendation 15 Virtual assets risk-based approach.
--   - FATF Recommendation 16 Travel Rule (counterparty VASP info).
--
-- Distinct from prior iters because the shape is **crypto-rail
-- back-office** (virtual-asset perspective):
--
--   - vs iter 204 winargpsp        — fiat payment rails (PSPCP).
--   - vs iter 203 winargsubcust    — foreign-investor securities.
--   - vs iter 202 winargtrustee    — bondholder trustee.
--   - vs iter 196 winargcrs        — CRS/FATCA reporting.
--   - vs iter 195 winargacdi       — fiat securities custody.
--
-- A VASP artifact leak is doubly-dangerous because:
--
--   * Wallet roster reveals customer-to-on-chain-address mapping
--     (= de-anonymizes blockchain analytics + makes addresses
--     attackable via dust / phishing).
--   * Hot/cold segregation map reveals exchange treasury topology
--     (= attack target list + cold-wallet ratios = exchange
--     solvency intel).
--   * Travel Rule (FATF Rec 16) counterparty messaging reveals
--     VASP-to-VASP customer transfers (= identifies which VASPs
--     are inter-connected + which customer transfers cross VASPs).
--   * On-chain analytics (Chainalysis / TRM / Elliptic) reveals
--     scoring methodology + risk flags (= adversary can engineer
--     transactions to evade detection).
--   * Sanctions screening result reveals OFAC / EU / UN hits and
--     mitigation logic (= sanctions-evasion engineering).
--   * Stablecoin redemption reveals USDT/USDC/DAI off-ramp
--     timing + counterparties (= run on stablecoin if leaked).
--   * DeFi protocol logs reveal Aave/Uniswap/Curve/dYdX integration
--     positions + bridge usage.
--   * UIF STR (Suspicious Transaction Report) under Res. 49 reveals
--     PSAV's suspicion-typology + customer targets (= AML defeat).
--   * AFIP RG 5697 filing reveals customer crypto holdings (= tax
--     enforcement intel + wealth attribution).
--   * Smart-contract audit reveals vulnerabilities pre-public
--     disclosure (= zero-day for the contract).
--
-- VASP distinctive features:
--
--   - Lemon Cash    Largest AR retail crypto exchange + PSPCP hybrid.
--   - Belo          Retail crypto + USDC stablecoin focus.
--   - Bitso AR      LatAm-anchored exchange + stablecoin rails.
--   - Ripio         OG AR crypto exchange (2013) + corporate.
--   - Buenbit       Retail + B2B exchange.
--   - SatoshiTango  Long-established AR exchange.
--   - Decrypto      AR OTC desk + institutional.
--   - Bitex         AR/LATAM B2B crypto-fiat bridge.
--   - Letsbit       AR retail exchange.
--   - BUDA AR       Chile-AR cross-border exchange.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\VASP\<year>\
--     wallet_roster_<chain>_<yyyymm>.csv         customer wallets
--     hot_cold_segregation_<yyyymm>.csv          treasury map
--     travel_rule_<yyyymmdd>.json                Rec 16 IVMS101
--     chain_analytics_<vendor>_<yyyymm>.csv      Chainalysis/TRM
--     sanctions_screening_<yyyymmdd>.csv         OFAC/EU/UN
--     stablecoin_redemption_<yyyymmdd>.csv       USDT/USDC/DAI
--     defi_interaction_<protocol>_<yyyymmdd>.csv Aave/Uniswap
--     bridge_swap_<yyyymmdd>.csv                 cross-chain
--     smart_contract_audit_<contract>.pdf        SCA report
--     kyc_tier_classification_<yyyymm>.csv       KYC tiers
--     afip_rg5697_<yyyy>q<n>.xml                 crypto tax
--     uif_str_<yyyymmdd>.pdf                     STR to UIF
--     cnv_rg1058_<yyyy>q<n>.xml                  PSAV registry
--     vasp_config.ini                            app config
--
-- Regulatory base:
--
--   Ley 27.739          FATF Rec 15+16 adoption
--   Ley 27.260          FATCA/CRS
--   CNV RG 1058/2024    PSAV registry
--   CNV RG 1023         Cyber
--   BCRA Com. A 8155    Crypto exposure
--   BCRA Com. A 7724    MULC
--   UIF Res. 49/2024    PLA/FT PSAV
--   UIF Res. 21/2018    PLA/FT general
--   AFIP RG 5697        Régimen cripto
--   Ley 25.246          PLA/FT marco
--   Ley 25.326          Datos Personales
--   Ley 27.401          Resp. penal
--   Ley 26.831 art.117  Insider
--   FATF Rec 15         Virtual assets
--   FATF Rec 16         Travel Rule
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (VASP vault)
--   T1552    Unsecured Credentials (hot-wallet seed)
--   T1078    Valid Accounts (VASP API)
--   T1005    Data from Local System (wallet roster)
--   T1530    Data from Cloud Storage
--   T1486    Data Encrypted for Impact (ransomware on VASP)
--   IVMS101         Travel Rule data model standard
--   BIP-39 / BIP-32 HD wallet standards
--   ERC-20 / ERC-721 / ERC-1155 token standards
--   SPL / TRC-20    Solana / Tron token standards
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-322 (key mgmt)
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_wallet_roster                — customer wallets list.
--   has_hot_cold_segregation         — treasury map.
--   has_travel_rule                  — Rec 16 IVMS101.
--   has_chain_analytics              — Chainalysis/TRM/Elliptic.
--   has_sanctions_screening          — OFAC/EU/UN.
--   has_stablecoin_redemption        — USDT/USDC/DAI redeem.
--   has_defi_interaction             — DeFi protocol logs.
--   has_bridge_swap                  — cross-chain bridge.
--   has_smart_contract_audit         — SCA report.
--   has_kyc_tier_classification      — KYC tiers.
--   has_afip_rg5697                  — crypto tax filing.
--   has_uif_str                      — STR to UIF.
--   has_cnv_rg1058                   — PSAV registry filing.
--   has_vasp_cuit                    — VASP entity CUIT.
--   has_wallet_address               — hashed wallet address.
--   has_seed_phrase_indicator        — seed-phrase marker.
--   has_large_redemption             — > 100K USD redemption.
--   has_sanctions_hit                — OFAC/EU/UN match.
--   is_credential_exposure_risk      — readable + password OR
--                                      seed indicator.
--   is_wallet_addr_pii_risk          — readable + (wallet roster
--                                      OR travel rule OR stablecoin
--                                      redemption OR KYC tier).
--   is_treasury_disclosure_risk      — readable + (hot/cold OR
--                                      cnv rg1058).
--   is_aml_screening_leak            — readable + (sanctions OR
--                                      chain analytics OR uif str
--                                      OR afip rg5697).

CREATE TABLE IF NOT EXISTS host_arg_vasp (
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
            'vasp-wallet-roster','vasp-hot-cold-segregation',
            'vasp-travel-rule','vasp-chain-analytics',
            'vasp-sanctions-screening','vasp-stablecoin-redemption',
            'vasp-defi-interaction','vasp-bridge-swap',
            'vasp-smart-contract-audit','vasp-kyc-tier-classification',
            'vasp-afip-rg5697-filing','vasp-uif-str',
            'vasp-cnv-rg1058-filing',
            'vasp-config','vasp-credentials',
            'vasp-installer','other','unknown'
        )),
    vasp_firm                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (vasp_firm IN (
            'lemon-cash','belo','bitso-ar','ripio',
            'buenbit','bitnovo-ar','satoshitango',
            'decrypto','bitex','letsbit','buda-ar',
            'custom','none','unknown'
        )),
    blockchain                  TEXT    NOT NULL DEFAULT ''
        CHECK (blockchain IN (
            '','bitcoin','ethereum','tron','solana',
            'polygon','arbitrum','optimism','base',
            'bsc','avalanche','bitcoin-cash','litecoin',
            'ripple','custom','none','unknown'
        )),
    token_class                 TEXT    NOT NULL DEFAULT ''
        CHECK (token_class IN (
            '','btc-native','erc20-stablecoin','erc20-utility',
            'trc20-stablecoin','sol-spl-stablecoin',
            'nft-erc721','nft-erc1155',
            'native-coin','wrapped-coin',
            'custom','none','unknown'
        )),
    travel_rule_status          TEXT    NOT NULL DEFAULT ''
        CHECK (travel_rule_status IN (
            '','compliant','pending','non-compliant',
            'self-hosted','below-threshold',
            'none','unknown'
        )),
    vasp_role                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (vasp_role IN (
            'compliance-officer','aml-officer',
            'chainalytics-analyst','treasury-officer',
            'security-engineer','back-office',
            'middle-office','cco','api',
            'other','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    vasp_cuit_prefix            TEXT    NOT NULL DEFAULT ''
        CHECK (vasp_cuit_prefix IN ('','30','33','34')),
    vasp_cuit_suffix4           TEXT    NOT NULL DEFAULT '',
    wallet_address_hash         TEXT    NOT NULL DEFAULT '',
    counterparty_vasp_hash      TEXT    NOT NULL DEFAULT '',
    wallet_count                INTEGER NOT NULL DEFAULT 0,
    customer_count              INTEGER NOT NULL DEFAULT 0,
    hot_wallet_balance_usd      INTEGER NOT NULL DEFAULT 0,
    cold_wallet_balance_usd     INTEGER NOT NULL DEFAULT 0,
    sanctions_hit_count         INTEGER NOT NULL DEFAULT 0,
    redemption_amount_usd       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_wallet_roster           INTEGER NOT NULL DEFAULT 0 CHECK (has_wallet_roster IN (0,1)),
    has_hot_cold_segregation    INTEGER NOT NULL DEFAULT 0 CHECK (has_hot_cold_segregation IN (0,1)),
    has_travel_rule             INTEGER NOT NULL DEFAULT 0 CHECK (has_travel_rule IN (0,1)),
    has_chain_analytics         INTEGER NOT NULL DEFAULT 0 CHECK (has_chain_analytics IN (0,1)),
    has_sanctions_screening     INTEGER NOT NULL DEFAULT 0 CHECK (has_sanctions_screening IN (0,1)),
    has_stablecoin_redemption   INTEGER NOT NULL DEFAULT 0 CHECK (has_stablecoin_redemption IN (0,1)),
    has_defi_interaction        INTEGER NOT NULL DEFAULT 0 CHECK (has_defi_interaction IN (0,1)),
    has_bridge_swap             INTEGER NOT NULL DEFAULT 0 CHECK (has_bridge_swap IN (0,1)),
    has_smart_contract_audit    INTEGER NOT NULL DEFAULT 0 CHECK (has_smart_contract_audit IN (0,1)),
    has_kyc_tier_classification INTEGER NOT NULL DEFAULT 0 CHECK (has_kyc_tier_classification IN (0,1)),
    has_afip_rg5697             INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_rg5697 IN (0,1)),
    has_uif_str                 INTEGER NOT NULL DEFAULT 0 CHECK (has_uif_str IN (0,1)),
    has_cnv_rg1058              INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_rg1058 IN (0,1)),
    has_vasp_cuit               INTEGER NOT NULL DEFAULT 0 CHECK (has_vasp_cuit IN (0,1)),
    has_wallet_address          INTEGER NOT NULL DEFAULT 0 CHECK (has_wallet_address IN (0,1)),
    has_seed_phrase_indicator   INTEGER NOT NULL DEFAULT 0 CHECK (has_seed_phrase_indicator IN (0,1)),
    has_large_redemption        INTEGER NOT NULL DEFAULT 0 CHECK (has_large_redemption IN (0,1)),
    has_sanctions_hit           INTEGER NOT NULL DEFAULT 0 CHECK (has_sanctions_hit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_wallet_addr_pii_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_wallet_addr_pii_risk IN (0,1)),
    is_treasury_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_treasury_disclosure_risk IN (0,1)),
    is_aml_screening_leak       INTEGER NOT NULL DEFAULT 0 CHECK (is_aml_screening_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_vasp_password
    ON host_arg_vasp(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_wallet
    ON host_arg_vasp(reporting_period, wallet_count) WHERE has_wallet_roster = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_treasury
    ON host_arg_vasp(reporting_period, hot_wallet_balance_usd, cold_wallet_balance_usd) WHERE has_hot_cold_segregation = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_travel
    ON host_arg_vasp(reporting_period, travel_rule_status) WHERE has_travel_rule = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_chain
    ON host_arg_vasp(reporting_period) WHERE has_chain_analytics = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_sanctions
    ON host_arg_vasp(reporting_period, sanctions_hit_count) WHERE has_sanctions_screening = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_stable
    ON host_arg_vasp(reporting_period, redemption_amount_usd) WHERE has_stablecoin_redemption = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_defi
    ON host_arg_vasp(reporting_period) WHERE has_defi_interaction = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_bridge
    ON host_arg_vasp(reporting_period) WHERE has_bridge_swap = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_sca
    ON host_arg_vasp(file_path) WHERE has_smart_contract_audit = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_kyc
    ON host_arg_vasp(reporting_period, customer_count) WHERE has_kyc_tier_classification = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_afip
    ON host_arg_vasp(reporting_period) WHERE has_afip_rg5697 = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_uif
    ON host_arg_vasp(reporting_period) WHERE has_uif_str = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_cnv
    ON host_arg_vasp(reporting_period) WHERE has_cnv_rg1058 = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_cuit
    ON host_arg_vasp(vasp_cuit_prefix, vasp_cuit_suffix4) WHERE has_vasp_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_addr
    ON host_arg_vasp(wallet_address_hash) WHERE has_wallet_address = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_seed
    ON host_arg_vasp(file_path) WHERE has_seed_phrase_indicator = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_redem
    ON host_arg_vasp(redemption_amount_usd) WHERE has_large_redemption = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_hit
    ON host_arg_vasp(sanctions_hit_count) WHERE has_sanctions_hit = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_cred_exp
    ON host_arg_vasp(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_pii
    ON host_arg_vasp(file_path) WHERE is_wallet_addr_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_treas_disc
    ON host_arg_vasp(file_path) WHERE is_treasury_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_aml
    ON host_arg_vasp(file_path) WHERE is_aml_screening_leak = 1;

CREATE INDEX IF NOT EXISTS idx_vasp_drift
    ON host_arg_vasp(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_vasp_kind
    ON host_arg_vasp(artifact_kind, vasp_firm);
