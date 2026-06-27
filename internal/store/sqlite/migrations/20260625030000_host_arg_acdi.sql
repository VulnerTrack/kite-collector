-- host_arg_acdi inventories AR ACDI (Agente de Colocación y
-- Distribución Integral, CNV RG 731 art.31 + RG 622) FCI
-- distributor artifact files cached on Argentine independent
-- FCI-distributor workstations.
--
-- ACDI sits between ALYC (iter 185 winargcohen) and FCI back-
-- office (iter 178 winargsintesis): no trade execution but
-- originates FCI subscriptions, runs client KYC + suitability,
-- manages retrocession fee chains with FCI managers (Cohen AM,
-- Galileo, Pellegrini, Sintesis-managed FCIs), and files
-- quarterly commission reports to CNV.
--
-- Distinct from prior iters because the shape is **distribution-
-- only back-office** (ACDI perspective, NO execution license):
--
--   - vs iter 185 winargcohen     — ALYC (execution + custody).
--   - vs iter 178 winargsintesis  — FCI manager back-office.
--   - vs iter 187 winargssn       — insurance institutional.
--
-- ACDI distinctive features:
--
--   - Distribution-only license (no settlement, no custody).
--   - Client KYC files (Ley 25.246 PLA/FT mandatory).
--   - Suitability assessment (CNV RG 622 art.31 — MiFID-equivalent
--     client classification: retail / pro / qualified investor).
--   - FCI subscription order forms (forwarded to FCI manager).
--   - Retrocession agreement with FCI manager (back-end load
--     sharing — typical 1% / yr split).
--   - Distribution agreement (contrato de distribución).
--   - Quarterly commission report to CNV.
--   - Client risk-profile questionnaire.
--   - PLA/FT cliente classification (UIF Res. 21/2018).
--
-- Headline finding shapes:
--
--   has_password_in_config        — cleartext.
--   has_client_kyc                — client KYC file.
--   has_suitability_assessment    — MiFID-equiv classification.
--   has_fci_subscription_order    — pending FCI subscription.
--   has_retrocession_agreement    — retrocession fee chain.
--   has_distribution_agreement    — ACDI ↔ FCI manager contract.
--   has_quarterly_commission_report — CNV filing.
--   has_client_risk_profile       — risk questionnaire.
--   has_plaft_classification      — UIF AML classification.
--   has_qualified_investor_flag   — investor pro / qualified.
--   has_cliente_cuit              — cliente CUIT.
--   has_cliente_dni               — cliente DNI (retail).
--   is_credential_exposure_risk   — readable + (password OR KYC
--                                   OR subscription order OR
--                                   commission report OR cuit/dni).
--   is_kyc_pii_risk               — readable + KYC + (cuit OR dni).

CREATE TABLE IF NOT EXISTS host_arg_acdi (
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
            'acdi-client-kyc','acdi-suitability-assessment',
            'acdi-fci-subscription-order',
            'acdi-retrocession-agreement',
            'acdi-distribution-agreement',
            'acdi-quarterly-commission-report',
            'acdi-client-risk-profile',
            'acdi-plaft-classification',
            'acdi-config','acdi-credentials',
            'acdi-installer','other','unknown'
        )),
    fci_manager                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (fci_manager IN (
            'cohen-am','galileo-am','pellegrini-am',
            'sintesis-managed','bbva-am','galicia-am',
            'santander-am','itau-am','adcap-am',
            'mariva-am','schweber','custom','none','unknown'
        )),
    client_classification       TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (client_classification IN (
            'retail','professional','qualified-investor',
            'institutional','knowledgeable-counterparty',
            'custom','none','unknown'
        )),
    plaft_risk_class            TEXT    NOT NULL DEFAULT ''
        CHECK (plaft_risk_class IN (
            '','low','medium','high','peps','beneficial-owner-unclear',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cliente_dni_hash            TEXT    NOT NULL DEFAULT '',
    acdi_license_id             TEXT    NOT NULL DEFAULT '',
    subscription_amount_ars_millions INTEGER NOT NULL DEFAULT 0,
    retrocession_bps            INTEGER NOT NULL DEFAULT 0,
    commission_total_ars_millions INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_client_kyc              INTEGER NOT NULL DEFAULT 0 CHECK (has_client_kyc IN (0,1)),
    has_suitability_assessment  INTEGER NOT NULL DEFAULT 0 CHECK (has_suitability_assessment IN (0,1)),
    has_fci_subscription_order  INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_subscription_order IN (0,1)),
    has_retrocession_agreement  INTEGER NOT NULL DEFAULT 0 CHECK (has_retrocession_agreement IN (0,1)),
    has_distribution_agreement  INTEGER NOT NULL DEFAULT 0 CHECK (has_distribution_agreement IN (0,1)),
    has_quarterly_commission_report INTEGER NOT NULL DEFAULT 0 CHECK (has_quarterly_commission_report IN (0,1)),
    has_client_risk_profile     INTEGER NOT NULL DEFAULT 0 CHECK (has_client_risk_profile IN (0,1)),
    has_plaft_classification    INTEGER NOT NULL DEFAULT 0 CHECK (has_plaft_classification IN (0,1)),
    has_qualified_investor_flag INTEGER NOT NULL DEFAULT 0 CHECK (has_qualified_investor_flag IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_cliente_dni             INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_dni IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_kyc_pii_risk             INTEGER NOT NULL DEFAULT 0 CHECK (is_kyc_pii_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_acdi_password
    ON host_arg_acdi(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_kyc
    ON host_arg_acdi(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_client_kyc = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_suitability
    ON host_arg_acdi(client_classification) WHERE has_suitability_assessment = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_subscription
    ON host_arg_acdi(fci_manager, subscription_amount_ars_millions) WHERE has_fci_subscription_order = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_retrocession
    ON host_arg_acdi(fci_manager, retrocession_bps) WHERE has_retrocession_agreement = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_commission
    ON host_arg_acdi(reporting_period, commission_total_ars_millions) WHERE has_quarterly_commission_report = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_plaft
    ON host_arg_acdi(plaft_risk_class) WHERE has_plaft_classification = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_qualified
    ON host_arg_acdi(client_classification) WHERE has_qualified_investor_flag = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_cliente
    ON host_arg_acdi(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_exposure
    ON host_arg_acdi(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_kyc_pii
    ON host_arg_acdi(file_path) WHERE is_kyc_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_acdi_drift
    ON host_arg_acdi(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_acdi_kind
    ON host_arg_acdi(artifact_kind, fci_manager);
