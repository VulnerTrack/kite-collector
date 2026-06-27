-- host_arg_trustee inventories AR ON-bondholder representative
-- (fiduciario representante de obligacionistas) artifact files
-- cached on trustee-officer, bondholder-rep, bondholder-counsel,
-- and back-office workstations at the institutions appointed
-- under CNV RG 622 art.41-bis to represent holders of corporate
-- Obligaciones Negociables (ON simple, convertible, subordinated,
-- secured, VRD-mixed, PyME, green, social, sustainability-linked).
--
-- Regulated under:
--
--   - Ley 23.576 (1988)          Régimen de Obligaciones Negociables.
--   - Ley 26.831 (2012)          Ley de Mercado de Capitales.
--   - Ley 27.260 (2016)          Reforma ON / fideicomisos.
--   - CNV RG 622 art.41-bis      Fiduciario representante de
--                                obligacionistas.
--   - CNV RG 622 art.41          Asamblea de obligacionistas.
--   - CNV RG 622 art.50          Audit trail.
--   - CNV RG 622 art.55          ON con garantía especial.
--   - BCRA Com. A 7916           Wholesale fiduciary trustee
--                                operational guidance.
--   - CNV RG 1023                Ciberresiliencia (2019).
--   - Ley 24.522 art.32-bis      Concursos preventivos (acreedores).
--   - Ley 27.401                 Responsabilidad penal jurídica.
--   - AFIP RG 4815               Exenciones impositivas ON.
--
-- Distinct from prior iters because the shape is **bondholder-
-- creditor-side trustee back-office** (creditor representation):
--
--   - vs iter 201 winargtesoro       — Tesoro primary issuance.
--   - vs iter 200 winargsgr          — SME mutual guarantee.
--   - vs iter 199 winargoms          — secondary market OMS.
--   - vs iter 189 winargfideicomiso  — SPV ABS issuer-side trust.
--   - vs iter 187 winargssn          — insurance reserves.
--   - vs iter 195 winargacdi         — generic custody.
--
-- A trustee artifact leak is doubly-dangerous because:
--
--   * Covenant-test result reveals issuer covenant breach pre-
--     publication (= MNPI for secondary-market ON pricing,
--     Ley 26.831 art.117 insider).
--   * Default notice reveals payment failure before public 8-K-
--     equivalent disclosure (= MNPI of credit event).
--   * Asamblea acta reveals creditor voting positions (=
--     reveals which bondholders will support / oppose restructuring).
--   * Workout negotiation reveals haircut / extension terms
--     pre-announcement (= material trading intel).
--   * Cash-flow distribution reveals beneficial-owner roster of
--     foreign + domestic ON holders (= front-running material
--     for secondary trades).
--   * Cross-acceleration trigger reveals chain-reaction default
--     across multi-instrument issuer obligations.
--   * Collateral monitoring reveals security-package value
--     impairment for secured ON (= MNPI on recovery rate).
--   * Trustee-fee invoice reveals issuer counsel + advisor lineup
--     (= early signal of restructuring engagement).
--
-- Trustee distinctive features:
--
--   - TMF Trust Argentina       Largest independent trustee.
--   - BNY Mellon Argentina      Global bank-affiliated.
--   - First Trust SA            Local fiduciario financiero.
--   - Equity Trust SA           Local trustee firm.
--   - BICE Fideicomisos         BICE Banco trust arm.
--   - Rosario Administradora SF Rosario-based.
--   - Cohen SA Trustee          ALYC-affiliated trustee.
--   - HSBC Trust                Global bank-affiliated.
--   - Santander Trust           Global bank-affiliated.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Trustee\<year>\
--     indenture_<issuer>_<series>.pdf          contrato emisión
--     covenant_test_<series>_<yyyymm>.xlsx     covenant test
--     default_notice_<series>_<yyyymmdd>.pdf   default notice
--     bondholder_meeting_<series>_<yyyymmdd>.pdf  asamblea acta
--     cash_flow_dist_<series>_<yyyymmdd>.csv   distribución
--     bondholder_roster_<series>_<yyyymm>.csv  lista titulares
--     workout_negotiation_<series>.pdf         reestructuración
--     rating_coordination_<series>.pdf         calificadora
--     cnv_filing_<series>_<yyyy>q<n>.xml       informe CNV
--     cross_acceleration_<series>.pdf          cross default
--     collateral_monitoring_<series>.xlsx      monitoreo garantías
--     trustee_fee_<series>_<yyyy>q<n>.pdf      fee invoice
--     trustee_config.ini                       app config
--
-- Regulatory base:
--
--   Ley 23.576       Régimen ON
--   Ley 26.831       Ley Mercado de Capitales
--   Ley 27.260       Reforma ON
--   CNV RG 622 art.41-bis  Fiduciario representante obligacionistas
--   CNV RG 622 art.41      Asamblea obligacionistas
--   CNV RG 622 art.50      Audit trail
--   CNV RG 622 art.55      ON con garantía especial
--   BCRA Com. A 7916       Wholesale trustee
--   CNV RG 1023            Ciberresiliencia
--   Ley 24.522 art.32-bis  Concursos
--   Ley 27.401             Responsabilidad penal jurídica
--   AFIP RG 4815           Exenciones ON
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (trustee vault)
--   T1552    Unsecured Credentials
--   T1005    Data from Local System (covenant test)
--   ISO 20022  Settlement message standards
--   ICMA       International Capital Market Association
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_indenture                    — contrato emisión.
--   has_covenant_test                — covenant compliance test.
--   has_default_notice               — default notice.
--   has_bondholder_meeting           — asamblea acta.
--   has_cash_flow_distribution       — distribución intereses/capital.
--   has_bondholder_roster            — lista titulares ON.
--   has_workout_negotiation          — reestructuración terms.
--   has_rating_coordination          — calificadora coord.
--   has_cnv_filing                   — informe trimestral CNV.
--   has_cross_acceleration_event     — cross default trigger.
--   has_collateral_monitoring        — monitoreo garantías.
--   has_trustee_fee                  — fee invoice.
--   has_issuer_cuit                  — issuer CUIT.
--   has_trustee_cuit                 — trustee firm CUIT.
--   has_covenant_breach              — issuer in breach.
--   is_credential_exposure_risk      — readable + password.
--   is_default_disclosure_risk       — readable + (default notice
--                                      OR covenant test in breach
--                                      OR cross acceleration).
--   is_workout_strategy_leak         — readable + (workout neg
--                                      OR rating coordination).
--   is_bondholder_pii_risk           — readable + (bondholder roster
--                                      OR cash flow distribution
--                                      OR bondholder meeting acta).

CREATE TABLE IF NOT EXISTS host_arg_trustee (
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
            'trustee-indenture','trustee-covenant-test',
            'trustee-default-notice','trustee-bondholder-meeting',
            'trustee-cash-flow-distribution','trustee-bondholder-roster',
            'trustee-workout-negotiation','trustee-rating-coordination',
            'trustee-cnv-filing','trustee-cross-acceleration',
            'trustee-collateral-monitoring','trustee-fee',
            'trustee-config','trustee-credentials',
            'trustee-installer','other','unknown'
        )),
    trustee_firm                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (trustee_firm IN (
            'tmf-trust','bny-mellon','first-trust',
            'equity-trust','bice','rosario-administradora',
            'cohen-trustee','hsbc-trust','santander-trust',
            'tmf-argentina','aval-federal-trust',
            'custom','none','unknown'
        )),
    trustee_role                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (trustee_role IN (
            'trustee-officer','bondholder-rep',
            'bondholder-counsel','back-office',
            'middle-office','compliance-officer',
            'cco','api','other','unknown'
        )),
    on_class                    TEXT    NOT NULL DEFAULT ''
        CHECK (on_class IN (
            '','on-simple','on-convertible','on-subordinated',
            'on-secured','on-vrd-mixed','on-pyme',
            'on-green-bond','on-social-bond',
            'on-sustainability-linked',
            'custom','none','unknown'
        )),
    default_status              TEXT    NOT NULL DEFAULT ''
        CHECK (default_status IN (
            '','performing','covenant-breach',
            'payment-default','cross-default',
            'acceleration','restructured',
            'collateral-execution',
            'none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    issuer_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (issuer_cuit_prefix IN ('','30','33','34')),
    issuer_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    trustee_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (trustee_cuit_prefix IN ('','30','33','34')),
    trustee_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    on_series_id                TEXT    NOT NULL DEFAULT '',
    bondholder_count            INTEGER NOT NULL DEFAULT 0,
    outstanding_principal_ars   INTEGER NOT NULL DEFAULT 0,
    accrued_interest_ars        INTEGER NOT NULL DEFAULT 0,
    covenant_breach_count       INTEGER NOT NULL DEFAULT 0,
    days_past_due               INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_indenture               INTEGER NOT NULL DEFAULT 0 CHECK (has_indenture IN (0,1)),
    has_covenant_test           INTEGER NOT NULL DEFAULT 0 CHECK (has_covenant_test IN (0,1)),
    has_default_notice          INTEGER NOT NULL DEFAULT 0 CHECK (has_default_notice IN (0,1)),
    has_bondholder_meeting      INTEGER NOT NULL DEFAULT 0 CHECK (has_bondholder_meeting IN (0,1)),
    has_cash_flow_distribution  INTEGER NOT NULL DEFAULT 0 CHECK (has_cash_flow_distribution IN (0,1)),
    has_bondholder_roster       INTEGER NOT NULL DEFAULT 0 CHECK (has_bondholder_roster IN (0,1)),
    has_workout_negotiation     INTEGER NOT NULL DEFAULT 0 CHECK (has_workout_negotiation IN (0,1)),
    has_rating_coordination     INTEGER NOT NULL DEFAULT 0 CHECK (has_rating_coordination IN (0,1)),
    has_cnv_filing              INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_filing IN (0,1)),
    has_cross_acceleration      INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_acceleration IN (0,1)),
    has_collateral_monitoring   INTEGER NOT NULL DEFAULT 0 CHECK (has_collateral_monitoring IN (0,1)),
    has_trustee_fee             INTEGER NOT NULL DEFAULT 0 CHECK (has_trustee_fee IN (0,1)),
    has_issuer_cuit             INTEGER NOT NULL DEFAULT 0 CHECK (has_issuer_cuit IN (0,1)),
    has_trustee_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_trustee_cuit IN (0,1)),
    has_covenant_breach         INTEGER NOT NULL DEFAULT 0 CHECK (has_covenant_breach IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_default_disclosure_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_default_disclosure_risk IN (0,1)),
    is_workout_strategy_leak    INTEGER NOT NULL DEFAULT 0 CHECK (is_workout_strategy_leak IN (0,1)),
    is_bondholder_pii_risk      INTEGER NOT NULL DEFAULT 0 CHECK (is_bondholder_pii_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_trustee_password
    ON host_arg_trustee(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_indenture
    ON host_arg_trustee(on_series_id) WHERE has_indenture = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_covenant
    ON host_arg_trustee(on_series_id, reporting_period, covenant_breach_count) WHERE has_covenant_test = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_default
    ON host_arg_trustee(on_series_id, default_status) WHERE has_default_notice = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_meeting
    ON host_arg_trustee(on_series_id, reporting_period) WHERE has_bondholder_meeting = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_dist
    ON host_arg_trustee(on_series_id, reporting_period) WHERE has_cash_flow_distribution = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_roster
    ON host_arg_trustee(on_series_id, bondholder_count) WHERE has_bondholder_roster = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_workout
    ON host_arg_trustee(on_series_id) WHERE has_workout_negotiation = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_rating
    ON host_arg_trustee(on_series_id) WHERE has_rating_coordination = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_cnv
    ON host_arg_trustee(on_series_id, reporting_period) WHERE has_cnv_filing = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_cross
    ON host_arg_trustee(on_series_id) WHERE has_cross_acceleration = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_collateral
    ON host_arg_trustee(on_series_id, reporting_period) WHERE has_collateral_monitoring = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_fee
    ON host_arg_trustee(on_series_id, reporting_period) WHERE has_trustee_fee = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_issuer
    ON host_arg_trustee(issuer_cuit_prefix, issuer_cuit_suffix4) WHERE has_issuer_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_firm
    ON host_arg_trustee(trustee_cuit_prefix, trustee_cuit_suffix4) WHERE has_trustee_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_breach
    ON host_arg_trustee(covenant_breach_count) WHERE has_covenant_breach = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_cred_exp
    ON host_arg_trustee(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_default_disc
    ON host_arg_trustee(file_path) WHERE is_default_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_workout_leak
    ON host_arg_trustee(file_path) WHERE is_workout_strategy_leak = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_bh_pii
    ON host_arg_trustee(file_path) WHERE is_bondholder_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_trustee_drift
    ON host_arg_trustee(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_trustee_kind
    ON host_arg_trustee(artifact_kind, on_class);
