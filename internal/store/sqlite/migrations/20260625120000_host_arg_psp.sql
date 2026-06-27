-- host_arg_psp inventories AR Payment-System-Processor (PSP /
-- PSPCP = Proveedores de Servicios de Pago que Ofrecen Cuentas
-- de Pago) artifact files cached on relationship-manager,
-- chargeback-officer, aml-officer, network-engineer, and
-- back-office workstations at Banelco, Link, Prisma Medios de
-- Pago, Mercado Pago, Ualá, Modo, Naranja X, Personal Pay,
-- Cuenta DNI BAPRO, Brubank, Lemon, Nubi, Belo — domestic
-- payment-rail intermediaries handling DEBIN push-debit,
-- CVU/CBU resolution, QR interoperable, ECHEQ, PIX-AR, Compe
-- clearing, Pago Mis Cuentas, VEP AFIP, and POS acquirer flows.
--
-- Regulated under:
--
--   - BCRA Com. A 7780       PSPCP + PSPOL (proveedores de
--                            servicios de pago).
--   - BCRA Com. A 8005       Ciberseguridad financiera (2024).
--   - BCRA Com. A 7153       QR código interoperable (2020).
--   - BCRA Com. A 4609       Sistema Nacional de Pagos.
--   - BCRA Com. A 7916       Riesgo crediticio mayorista.
--   - BCRA Com. A 7724       MULC (cross-border PSP).
--   - AFIP RG 4636           VEP / cheques digitales.
--   - AFIP RG 4040           Régimen información PSPCP.
--   - UIF Res. 76/2019       PLA/FT específico PSPCP.
--   - UIF Res. 21/2018       PLA/FT entidades financieras.
--   - Ley 25.246             Encubrimiento + LA.
--   - Ley 25.326             Datos Personales.
--   - Ley 26.831 art.117     Insider (cuando coincide con
--                            cuenta-bursátil PSP).
--   - Ley 27.401             Responsabilidad penal jurídica.
--   - Ley 27.265             Cuenta gratuita universal.
--   - Decreto 27/2018        DEBIN regulation.
--
-- Distinct from prior iters because the shape is **payment-rail
-- back-office** (not securities trading / custody / order-
-- routing):
--
--   - vs iter 203 winargsubcust    — foreign-investor custody.
--   - vs iter 202 winargtrustee    — bondholder trustee.
--   - vs iter 201 winargtesoro     — Tesoro primary issuance.
--   - vs iter 199 winargoms        — secondary-market OMS.
--   - vs iter 195 winargacdi       — securities custody.
--   - vs iter 185 winargcohen      — ALYC trading desk.
--
-- A PSP artifact leak is doubly-dangerous because:
--
--   * DEBIN batch reveals push-debit consents + payer CBU + amount
--     (= mass account-takeover targeting + payee identification).
--   * CVU/CBU/Alias resolution log reveals lookup activity (=
--     reverse-lookup attack: bulk validate CVUs against alias
--     namespace, then bulk-DEBIN the validated ones).
--   * QR interoperable code generation reveals merchant payment
--     IDs (= QR replay / phishing-QR targeting).
--   * ECHEQ issuance reveals digital-cheque payer + payee + serial
--     (= cheque cloning / forgery enablement).
--   * PIX-AR instant batch reveals payment timing/size (= instant
--     fraud window).
--   * Compe clearing batch reveals net positions among banks (=
--     interbank liquidity intel).
--   * Merchant onboarding KYC reveals merchant DNI/CUIT/CBU + AFIP
--     status (= PSPCP customer database = high-value PII).
--   * BCRA información régimen reveals aggregate flow data (=
--     reverse-engineer PSP market share).
--   * AML / UIF data reveals typology + STR-equivalent reports
--     (= AML-defeat intel for adversaries).
--   * POS acquirer batch reveals card terminal IDs (= terminal-
--     spoofing / card-present fraud target list).
--
-- PSP distinctive features:
--
--   - Banelco / Link — ATM / debit-card switching networks.
--   - Prisma Medios de Pago — Visa / Mastercard AR acquirer.
--   - Mercado Pago — by volume largest PSPCP in AR.
--   - Ualá / Modo / Naranja X / Personal Pay — neobank PSPCPs.
--   - Cuenta DNI BAPRO — provincial-bank PSPCP.
--   - Brubank — digital-bank PSPCP.
--   - Lemon / Nubi / Belo — crypto-PSP hybrids.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\PSP\<year>\
--     debin_batch_<yyyymmdd>.csv                 DEBIN push-debit
--     cvu_cbu_resolution_<yyyymmdd>.csv          CVU resolve log
--     qr_interoperable_<yyyymmdd>.csv            QR codes
--     echeq_issuance_<yyyymmdd>.csv              ECHEQ batch
--     pix_ar_batch_<yyyymmdd>.csv                PIX-AR instant
--     compe_clearing_<yyyymmdd>.csv              Compe batch
--     pago_mis_cuentas_<yyyymmdd>.csv            PMC reconcile
--     vep_afip_<yyyymmdd>.csv                    VEP AFIP
--     pos_acquirer_batch_<yyyymmdd>.csv          POS acquirer
--     cash_out_batch_<yyyymmdd>.csv              cash-out merchants
--     merchant_onboarding_<yyyymm>.csv           KYC merchant
--     bcra_info_regimen_<yyyymm>.xml             BCRA info regimen
--     psp_config.ini                             app config
--
-- Regulatory base:
--
--   BCRA Com. A 7780   PSPCP + PSPOL
--   BCRA Com. A 8005   Ciberseguridad
--   BCRA Com. A 7153   QR interoperable
--   BCRA Com. A 4609   Sistema Nacional Pagos
--   BCRA Com. A 7916   Riesgo crediticio
--   BCRA Com. A 7724   MULC
--   AFIP RG 4636       VEP / cheques digitales
--   AFIP RG 4040       Régimen PSPCP
--   UIF Res. 76/2019   PLA/FT PSPCP
--   UIF Res. 21/2018   PLA/FT entidades
--   Ley 25.246         PLA/FT
--   Ley 25.326         Datos Personales
--   Ley 26.831 art.117 Insider
--   Ley 27.401         Resp. penal jurídica
--   Ley 27.265         Cuenta gratuita universal
--   Decreto 27/2018    DEBIN
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (PSP vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (PSP API)
--   T1005    Data from Local System (DEBIN batch)
--   T1565    Data Manipulation (chargeback fraud)
--   ISO 20022     Settlement message standards
--   ISO 8583      Card-payment messaging
--   EMV           Card-present standards
--   PCI-DSS       Payment Card Industry
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-841
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_debin_batch                  — DEBIN push-debit batch.
--   has_cvu_cbu_resolution           — CVU resolve log.
--   has_qr_interoperable             — QR codes.
--   has_echeq_issuance               — ECHEQ batch.
--   has_pix_ar_batch                 — PIX-AR instant.
--   has_compe_clearing               — Compe batch.
--   has_pago_mis_cuentas             — PMC reconcile.
--   has_vep_afip                     — VEP AFIP.
--   has_pos_acquirer_batch           — POS acquirer.
--   has_cash_out_batch               — cash-out merchants.
--   has_merchant_onboarding          — KYC merchant.
--   has_bcra_info_regimen            — BCRA regimen.
--   has_psp_cuit                     — PSP entity CUIT.
--   has_customer_cvu                 — customer CVU hashed.
--   has_large_batch_value            — batch > 1B ARS.
--   is_credential_exposure_risk      — readable + password OR
--                                      api key.
--   is_payment_pii_risk              — readable + (DEBIN OR
--                                      CVU/CBU resolution OR
--                                      merchant onboarding).
--   is_aml_typology_leak             — readable + (BCRA info
--                                      regimen OR merchant KYC).
--   is_settlement_chain_disclosure   — readable + (Compe OR PIX-AR
--                                      OR ECHEQ OR pos acquirer).

CREATE TABLE IF NOT EXISTS host_arg_psp (
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
            'psp-debin-batch','psp-cvu-cbu-resolution',
            'psp-qr-interoperable','psp-echeq-issuance',
            'psp-pix-ar-batch','psp-compe-clearing',
            'psp-pago-mis-cuentas','psp-vep-afip',
            'psp-pos-acquirer-batch','psp-cash-out-batch',
            'psp-merchant-onboarding','psp-bcra-info-regimen',
            'psp-config','psp-credentials',
            'psp-installer','other','unknown'
        )),
    psp_network                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (psp_network IN (
            'banelco','link','prisma','mercado-pago',
            'uala','modo','naranja-x','personal-pay',
            'cuenta-dni-bapro','brubank','lemon','nubi','belo',
            'custom','none','unknown'
        )),
    settlement_rail             TEXT    NOT NULL DEFAULT ''
        CHECK (settlement_rail IN (
            '','compe','mep','coelsa','debin',
            'transfer-3-0','pix-ar',
            'custom','none','unknown'
        )),
    psp_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (psp_role IN (
            'relationship-manager','chargeback-officer',
            'aml-officer','back-office','middle-office',
            'compliance-officer','network-engineer',
            'cco','api','other','unknown'
        )),
    transaction_type            TEXT    NOT NULL DEFAULT ''
        CHECK (transaction_type IN (
            '','p2p','p2m','m2p','b2b','payroll',
            'vep-afip','tax-collection','utility-payment',
            'subscription',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    psp_cuit_prefix             TEXT    NOT NULL DEFAULT ''
        CHECK (psp_cuit_prefix IN ('','30','33','34')),
    psp_cuit_suffix4            TEXT    NOT NULL DEFAULT '',
    customer_cvu_hash           TEXT    NOT NULL DEFAULT '',
    merchant_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (merchant_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    merchant_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    batch_id                    TEXT    NOT NULL DEFAULT '',
    transaction_count           INTEGER NOT NULL DEFAULT 0,
    customer_count              INTEGER NOT NULL DEFAULT 0,
    merchant_count              INTEGER NOT NULL DEFAULT 0,
    batch_value_ars             INTEGER NOT NULL DEFAULT 0,
    chargeback_count            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_debin_batch             INTEGER NOT NULL DEFAULT 0 CHECK (has_debin_batch IN (0,1)),
    has_cvu_cbu_resolution      INTEGER NOT NULL DEFAULT 0 CHECK (has_cvu_cbu_resolution IN (0,1)),
    has_qr_interoperable        INTEGER NOT NULL DEFAULT 0 CHECK (has_qr_interoperable IN (0,1)),
    has_echeq_issuance          INTEGER NOT NULL DEFAULT 0 CHECK (has_echeq_issuance IN (0,1)),
    has_pix_ar_batch            INTEGER NOT NULL DEFAULT 0 CHECK (has_pix_ar_batch IN (0,1)),
    has_compe_clearing          INTEGER NOT NULL DEFAULT 0 CHECK (has_compe_clearing IN (0,1)),
    has_pago_mis_cuentas        INTEGER NOT NULL DEFAULT 0 CHECK (has_pago_mis_cuentas IN (0,1)),
    has_vep_afip                INTEGER NOT NULL DEFAULT 0 CHECK (has_vep_afip IN (0,1)),
    has_pos_acquirer_batch      INTEGER NOT NULL DEFAULT 0 CHECK (has_pos_acquirer_batch IN (0,1)),
    has_cash_out_batch          INTEGER NOT NULL DEFAULT 0 CHECK (has_cash_out_batch IN (0,1)),
    has_merchant_onboarding     INTEGER NOT NULL DEFAULT 0 CHECK (has_merchant_onboarding IN (0,1)),
    has_bcra_info_regimen       INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_info_regimen IN (0,1)),
    has_psp_cuit                INTEGER NOT NULL DEFAULT 0 CHECK (has_psp_cuit IN (0,1)),
    has_customer_cvu            INTEGER NOT NULL DEFAULT 0 CHECK (has_customer_cvu IN (0,1)),
    has_merchant_cuit           INTEGER NOT NULL DEFAULT 0 CHECK (has_merchant_cuit IN (0,1)),
    has_large_batch_value       INTEGER NOT NULL DEFAULT 0 CHECK (has_large_batch_value IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_payment_pii_risk         INTEGER NOT NULL DEFAULT 0 CHECK (is_payment_pii_risk IN (0,1)),
    is_aml_typology_leak        INTEGER NOT NULL DEFAULT 0 CHECK (is_aml_typology_leak IN (0,1)),
    is_settlement_chain_disclosure INTEGER NOT NULL DEFAULT 0 CHECK (is_settlement_chain_disclosure IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_psp_password
    ON host_arg_psp(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_psp_debin
    ON host_arg_psp(reporting_period, transaction_count) WHERE has_debin_batch = 1;

CREATE INDEX IF NOT EXISTS idx_psp_cvu
    ON host_arg_psp(reporting_period) WHERE has_cvu_cbu_resolution = 1;

CREATE INDEX IF NOT EXISTS idx_psp_qr
    ON host_arg_psp(reporting_period) WHERE has_qr_interoperable = 1;

CREATE INDEX IF NOT EXISTS idx_psp_echeq
    ON host_arg_psp(reporting_period) WHERE has_echeq_issuance = 1;

CREATE INDEX IF NOT EXISTS idx_psp_pix
    ON host_arg_psp(reporting_period, transaction_count) WHERE has_pix_ar_batch = 1;

CREATE INDEX IF NOT EXISTS idx_psp_compe
    ON host_arg_psp(reporting_period) WHERE has_compe_clearing = 1;

CREATE INDEX IF NOT EXISTS idx_psp_pmc
    ON host_arg_psp(reporting_period) WHERE has_pago_mis_cuentas = 1;

CREATE INDEX IF NOT EXISTS idx_psp_vep
    ON host_arg_psp(reporting_period) WHERE has_vep_afip = 1;

CREATE INDEX IF NOT EXISTS idx_psp_pos
    ON host_arg_psp(reporting_period) WHERE has_pos_acquirer_batch = 1;

CREATE INDEX IF NOT EXISTS idx_psp_cashout
    ON host_arg_psp(reporting_period) WHERE has_cash_out_batch = 1;

CREATE INDEX IF NOT EXISTS idx_psp_kyc
    ON host_arg_psp(reporting_period, merchant_count) WHERE has_merchant_onboarding = 1;

CREATE INDEX IF NOT EXISTS idx_psp_regimen
    ON host_arg_psp(reporting_period) WHERE has_bcra_info_regimen = 1;

CREATE INDEX IF NOT EXISTS idx_psp_psp_cuit
    ON host_arg_psp(psp_cuit_prefix, psp_cuit_suffix4) WHERE has_psp_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_psp_customer
    ON host_arg_psp(customer_cvu_hash) WHERE has_customer_cvu = 1;

CREATE INDEX IF NOT EXISTS idx_psp_merchant
    ON host_arg_psp(merchant_cuit_prefix, merchant_cuit_suffix4) WHERE has_merchant_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_psp_large_batch
    ON host_arg_psp(batch_value_ars) WHERE has_large_batch_value = 1;

CREATE INDEX IF NOT EXISTS idx_psp_cred_exp
    ON host_arg_psp(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_psp_pay_pii
    ON host_arg_psp(file_path) WHERE is_payment_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_psp_aml_leak
    ON host_arg_psp(file_path) WHERE is_aml_typology_leak = 1;

CREATE INDEX IF NOT EXISTS idx_psp_chain
    ON host_arg_psp(file_path) WHERE is_settlement_chain_disclosure = 1;

CREATE INDEX IF NOT EXISTS idx_psp_drift
    ON host_arg_psp(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_psp_kind
    ON host_arg_psp(artifact_kind, psp_network);
