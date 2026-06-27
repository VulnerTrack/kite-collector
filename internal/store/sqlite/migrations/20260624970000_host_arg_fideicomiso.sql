-- host_arg_fideicomiso inventories AR Fideicomiso Financiero (FF
-- — trust / securitization vehicle) artifact files cached on
-- Argentine fiduciario, structurer, and trust-administrator
-- workstations.
--
-- AR Fideicomisos Financieros are the main securitization vehicle
-- in AR capital markets — they pool consumer-finance receivables
-- (Tarjeta Naranja, Cetelem, Garbarino), mortgages, PYME loans,
-- and real-estate developments into tradeable trust certificates
-- listed on BYMA and custodied at Caja de Valores. Regulated under
-- CNV RG 622 art.42 + Ley 24.441 (Fideicomiso Civil) + Ley 26.831
-- (Mercado de Capitales).
--
-- Distinct from prior iters because the shape is **trust-company
-- back-office** (fiduciario perspective):
--
--   - vs iter 188 winargfgs       — sovereign-wealth-fund.
--   - vs iter 187 winargssn       — private insurer investor.
--   - vs iter 185 winargcohen     — broker-dealer ALYC.
--   - vs iter 178 winargsintesis  — FCI back-office.
--
-- Trust certificates (VRD — Valor Representativo de Deuda, CP —
-- Certificado de Participación) issued by Fideicomisos Financieros
-- are held by SSN insurers, FGS, Cohen AM FCIs, and retail
-- investors via Cocos/Balanz/Allaria — all collectors I already
-- built. Leakage of the issuance-side data (collections cohort,
-- mora cohort, investor list) feeds into:
--
--   - Underlying-loan-pool exposure (CWE-200 on consumer credit).
--   - Investor concentration analysis (who holds which series).
--   - Default-prediction model training data (mora cohort).
--   - Fiduciario fee structure (originator/servicer/agent fees).
--
-- AR Fideicomiso distinctive features:
--
--   - Two-track trust types: Civil (Ley 24.441) and Financiero
--     (Ley 26.831 art.4 + CNV RG 622 art.42 — public-issuance
--     subject to CNV disclosure).
--   - VRD (Valor Representativo de Deuda) — debt-tranche certs.
--   - CP (Certificado de Participación) — equity-tranche certs.
--   - Originador (originator) — entity selling the receivables.
--   - Fiduciario (trustee) — BACS, TMF Argentina, First Trust.
--   - Agente de Control y Revisión (control agent) — auditor.
--   - Cobranza monthly CSV — payment collections by receivable.
--   - Mora monthly CSV — default cohort by receivable.
--   - Precancelación — early repayment events.
--   - Suplemento serie — per-tranche supplement to prospecto.
--   - Calificación de riesgo (rating) — FIX SCR, Moody's, S&P.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Fideicomiso\<ff_name>\
--     prospecto.pdf                                    base prospecto
--     suplemento_<series>.pdf                          per-series
--     escritura_fiduciaria.pdf                         trust deed
--     contrato_fiduciario.pdf                          trust contract
--     cobranza_<period>.csv                            collections
--     mora_<period>.csv                                defaults
--     precancelacion_<period>.csv                      prepayments
--     titulo_<series>.xml                              trust cert
--     inversores_<series>.csv                          investor list
--     calificacion_<series>.pdf                        rating report
--     reporte_administrador_<period>.pdf               admin report
--     auditoria_<period>.pdf                           audit report
--   %USERPROFILE%\Documents\Fideicomiso\               docs root
--
-- Fideicomiso-specific risk signals:
--
--   * Cleartext password in fiduciario-tool config = T1552 + CNV
--     RG 1023.
--   * Cobranza CSV with raw cliente CUIT + raw receivable amount =
--     consumer-credit PII vault (Ley 25.326 + BCRA CDD privacy).
--   * Mora CSV with cliente CUIT + default tag = adverse-credit
--     PII (T1213; lifetime affect on cliente's BCRA Central de
--     Deudores rating).
--   * Investor list with cliente CUIT = primary-distribution-side
--     PII (CNV RG 622 art.42 transparency vs. Ley 25.326 privacy
--     conflict).
--   * Escritura fiduciaria readable = contract-law disclosure
--     (Ley 24.441 art.4 publicness vs. internal-draft phase).
--   * Pre-issuance suplemento (draft) = insider-information regime
--     (CNV RG 622 art.50; price-impact on listed VRD/CP).
--   * Originador kicks-back fee structure = M&A-style sensitivity
--     (CWE-200 across originator/servicer/fiduciario fee chain).
--
-- Regulatory base:
--
--   Ley 24.441    Financiamiento de la Vivienda (Fideicomiso Civil)
--   Ley 26.831    Mercado de Capitales art.4 (Fideicomiso Fin.)
--   CNV RG 622 art.42  Fideicomisos Financieros disclosure
--   CNV RG 622 art.50  Insider information
--   CNV RG 731    Régimen de Agentes (fiduciario licensing)
--   CNV RG 1023   Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias (USD FF)
--   AFIP RG 5193  Securities tax reporting
--   AFIP F.8125   Cross-border transfer
--   Ley 25.326    Datos Personales (cobranza PII)
--   Ley 25.246    PLA/FT (investor KYC)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (cobranza vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (fiduciario portal)
--   T1005    Data from Local System (escritura, suplemento)
--   T1199    Trusted Relationship (originador ↔ fiduciario chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config         — fiduciario-tool cleartext.
--   has_prospecto                  — base prospecto.
--   has_suplemento_serie           — per-tranche supplement.
--   has_escritura_fiduciaria       — trust deed.
--   has_contrato_fiduciario        — trust contract.
--   has_cobranza_csv               — collections cohort.
--   has_mora_csv                   — default cohort.
--   has_precancelacion_csv         — prepayment cohort.
--   has_titulo_serie               — trust certificate.
--   has_investor_list              — primary-distribution list.
--   has_calificacion_report        — rating report.
--   has_administrator_report       — admin / fiduciario report.
--   has_audit_report               — Agente de Control output.
--   has_pre_issuance_draft         — draft suplemento (insider).
--   has_consumer_credit_pii        — cobranza/mora with CUIT.
--   has_adverse_credit_event       — mora with cliente CUIT.
--   has_cliente_cuit               — cliente CUIT detected.
--   has_originador_cuit            — originador entity CUIT.
--   is_credential_exposure_risk    — readable + (password OR
--                                    prospecto OR cobranza OR
--                                    investor list OR cliente CUIT).
--   is_consumer_credit_pii_risk    — readable + cobranza/mora +
--                                    cliente CUIT.
--   is_insider_information_risk    — readable + (pre-issuance
--                                    draft OR escritura OR
--                                    administrator report).

CREATE TABLE IF NOT EXISTS host_arg_fideicomiso (
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
            'ff-prospecto','ff-suplemento-serie',
            'ff-escritura-fiduciaria','ff-contrato-fiduciario',
            'ff-cobranza-csv','ff-mora-csv',
            'ff-precancelacion-csv',
            'ff-titulo-serie','ff-investor-list',
            'ff-calificacion-report','ff-administrator-report',
            'ff-audit-report','ff-filing-receipt',
            'ff-config','ff-credentials',
            'ff-installer','other','unknown'
        )),
    trust_role                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (trust_role IN (
            'fiduciario','originador','servicer',
            'agente-control-revision','underwriter',
            'colocador','calificadora','custodio',
            'compliance-officer','api','other','unknown'
        )),
    underlying_class            TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (underlying_class IN (
            'consumer-credit','tarjeta-credito',
            'mortgage','prendario','leasing',
            'pyme-loan','sgr-pool',
            'real-estate-dev','agro-commodity',
            'export-pre-financing','export-bill',
            'multi-asset','other','unknown'
        )),
    tranche_class               TEXT    NOT NULL DEFAULT ''
        CHECK (tranche_class IN (
            '','vrd-senior','vrd-mezzanine','vrd-subordinated',
            'cp-equity','cp-senior',
            'custom','none','unknown'
        )),
    rating_class                TEXT    NOT NULL DEFAULT ''
        CHECK (rating_class IN (
            '','aaa','aa','a','bbb','bb','b','ccc','cc','c','d',
            'no-rating','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    originador_cuit_prefix      TEXT    NOT NULL DEFAULT ''
        CHECK (originador_cuit_prefix IN ('','30','33','34')),
    originador_cuit_suffix4     TEXT    NOT NULL DEFAULT '',
    fiduciario_cuit_prefix      TEXT    NOT NULL DEFAULT ''
        CHECK (fiduciario_cuit_prefix IN ('','30','33','34')),
    fiduciario_cuit_suffix4     TEXT    NOT NULL DEFAULT '',
    ff_name_hash                TEXT    NOT NULL DEFAULT '',
    series_id                   TEXT    NOT NULL DEFAULT '',
    cnv_authorization_id        TEXT    NOT NULL DEFAULT '',
    receivable_count            INTEGER NOT NULL DEFAULT 0,
    collection_total_ars_millions INTEGER NOT NULL DEFAULT 0,
    mora_count                  INTEGER NOT NULL DEFAULT 0,
    mora_amount_ars_millions    INTEGER NOT NULL DEFAULT 0,
    investor_count              INTEGER NOT NULL DEFAULT 0,
    issuance_amount_ars_millions INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_prospecto               INTEGER NOT NULL DEFAULT 0 CHECK (has_prospecto IN (0,1)),
    has_suplemento_serie        INTEGER NOT NULL DEFAULT 0 CHECK (has_suplemento_serie IN (0,1)),
    has_escritura_fiduciaria    INTEGER NOT NULL DEFAULT 0 CHECK (has_escritura_fiduciaria IN (0,1)),
    has_contrato_fiduciario     INTEGER NOT NULL DEFAULT 0 CHECK (has_contrato_fiduciario IN (0,1)),
    has_cobranza_csv            INTEGER NOT NULL DEFAULT 0 CHECK (has_cobranza_csv IN (0,1)),
    has_mora_csv                INTEGER NOT NULL DEFAULT 0 CHECK (has_mora_csv IN (0,1)),
    has_precancelacion_csv      INTEGER NOT NULL DEFAULT 0 CHECK (has_precancelacion_csv IN (0,1)),
    has_titulo_serie            INTEGER NOT NULL DEFAULT 0 CHECK (has_titulo_serie IN (0,1)),
    has_investor_list           INTEGER NOT NULL DEFAULT 0 CHECK (has_investor_list IN (0,1)),
    has_calificacion_report     INTEGER NOT NULL DEFAULT 0 CHECK (has_calificacion_report IN (0,1)),
    has_administrator_report    INTEGER NOT NULL DEFAULT 0 CHECK (has_administrator_report IN (0,1)),
    has_audit_report            INTEGER NOT NULL DEFAULT 0 CHECK (has_audit_report IN (0,1)),
    has_pre_issuance_draft      INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_issuance_draft IN (0,1)),
    has_consumer_credit_pii     INTEGER NOT NULL DEFAULT 0 CHECK (has_consumer_credit_pii IN (0,1)),
    has_adverse_credit_event    INTEGER NOT NULL DEFAULT 0 CHECK (has_adverse_credit_event IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_originador_cuit         INTEGER NOT NULL DEFAULT 0 CHECK (has_originador_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_consumer_credit_pii_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_consumer_credit_pii_risk IN (0,1)),
    is_insider_information_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_insider_information_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ff_password
    ON host_arg_fideicomiso(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ff_prospecto
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_prospecto = 1;

CREATE INDEX IF NOT EXISTS idx_ff_suplemento
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_suplemento_serie = 1;

CREATE INDEX IF NOT EXISTS idx_ff_escritura
    ON host_arg_fideicomiso(series_id) WHERE has_escritura_fiduciaria = 1;

CREATE INDEX IF NOT EXISTS idx_ff_cobranza
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_cobranza_csv = 1;

CREATE INDEX IF NOT EXISTS idx_ff_mora
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_mora_csv = 1;

CREATE INDEX IF NOT EXISTS idx_ff_precancelacion
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_precancelacion_csv = 1;

CREATE INDEX IF NOT EXISTS idx_ff_titulo
    ON host_arg_fideicomiso(series_id, tranche_class) WHERE has_titulo_serie = 1;

CREATE INDEX IF NOT EXISTS idx_ff_investor
    ON host_arg_fideicomiso(series_id, investor_count) WHERE has_investor_list = 1;

CREATE INDEX IF NOT EXISTS idx_ff_calificacion
    ON host_arg_fideicomiso(series_id, rating_class) WHERE has_calificacion_report = 1;

CREATE INDEX IF NOT EXISTS idx_ff_administrator
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_administrator_report = 1;

CREATE INDEX IF NOT EXISTS idx_ff_audit
    ON host_arg_fideicomiso(series_id, reporting_period) WHERE has_audit_report = 1;

CREATE INDEX IF NOT EXISTS idx_ff_pre_issuance
    ON host_arg_fideicomiso(series_id) WHERE has_pre_issuance_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ff_consumer_credit
    ON host_arg_fideicomiso(series_id, receivable_count) WHERE has_consumer_credit_pii = 1;

CREATE INDEX IF NOT EXISTS idx_ff_adverse
    ON host_arg_fideicomiso(series_id, mora_count) WHERE has_adverse_credit_event = 1;

CREATE INDEX IF NOT EXISTS idx_ff_cliente
    ON host_arg_fideicomiso(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ff_originador
    ON host_arg_fideicomiso(originador_cuit_prefix, originador_cuit_suffix4) WHERE has_originador_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ff_exposure
    ON host_arg_fideicomiso(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ff_consumer_pii
    ON host_arg_fideicomiso(file_path) WHERE is_consumer_credit_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ff_insider
    ON host_arg_fideicomiso(file_path) WHERE is_insider_information_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ff_drift
    ON host_arg_fideicomiso(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ff_kind
    ON host_arg_fideicomiso(artifact_kind, trust_role);
