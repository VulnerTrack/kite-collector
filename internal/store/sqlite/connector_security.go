// connector_security.go: SQLite persistence for the connector hardening posture
// (RFC-0137 R9). Backs the ConnectorSecurityProfile and ConnectorGuardEvent
// ontology classes with a real Go-side source that the RFC-0033 bridge syncs to
// ClickHouse. connector_security_profiles was created by RFC-0135's migration
// 20260710000000 and extended with credential_privilege_tier by RFC-0137's
// migration 20260712000000, which also creates connector_guard_event.
package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
)

// UpsertConnectorSecurityProfile appends a code-derived security-profile
// assessment for one connector. Profiles are append-only history keyed by
// (source_name, assessed_at): a new assessment supersedes the previous one by
// carrying a fresh timestamp (RFC-0137 4.2.1), so the ontology timeline retains
// every posture change. Empty tls_mode / credential_privilege_tier are defaulted
// so the tls_mode CHECK constraint is always satisfied.
func (s *SQLiteStore) UpsertConnectorSecurityProfile(ctx context.Context, p connectorkit.SecurityProfile) error {
	_, err := s.db.ExecContext(
		ctx, `
		INSERT INTO connector_security_profiles (
			source_name, endpoint_validated, path_segments_sanitized,
			pagination_guarded, tls_mode, credentials_zeroed,
			enabled_flag_respected, circuit_breaker_attached,
			credential_privilege_tier, hardening_score, assessed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
		ON CONFLICT(source_name, assessed_at) DO UPDATE SET
			endpoint_validated        = excluded.endpoint_validated,
			path_segments_sanitized   = excluded.path_segments_sanitized,
			pagination_guarded        = excluded.pagination_guarded,
			tls_mode                  = excluded.tls_mode,
			credentials_zeroed        = excluded.credentials_zeroed,
			enabled_flag_respected    = excluded.enabled_flag_respected,
			circuit_breaker_attached  = excluded.circuit_breaker_attached,
			credential_privilege_tier = excluded.credential_privilege_tier,
			hardening_score           = excluded.hardening_score
	`,
		p.SourceName,
		boolToInt(p.EndpointValidated),
		boolToInt(p.PathSegmentsSanitized),
		boolToInt(p.PaginationGuarded),
		tlsModeOrDefault(p.TLSMode),
		boolToInt(p.CredentialsZeroed),
		boolToInt(p.EnabledFlagRespected),
		boolToInt(p.CircuitBreakerAttached),
		tierOrDefault(p.CredentialPrivilegeTier),
		p.HardeningScore,
	)
	if err != nil {
		return fmt.Errorf("upsert connector security profile %s: %w", p.SourceName, err)
	}
	return nil
}

// ListConnectorSecurityProfiles returns the most recent profile per source,
// ordered by source_name. It powers the GET /api/v1/connector-security-profiles
// surface (RFC-0137 5.4). A missing table (un-migrated DB) yields an empty slice
// rather than an error, matching the other read paths.
func (s *SQLiteStore) ListConnectorSecurityProfiles(ctx context.Context) ([]connectorkit.SecurityProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source_name, endpoint_validated, path_segments_sanitized,
			pagination_guarded, tls_mode, credentials_zeroed,
			enabled_flag_respected, circuit_breaker_attached,
			credential_privilege_tier, hardening_score
		FROM connector_security_profiles AS p
		WHERE assessed_at = (
			SELECT MAX(assessed_at) FROM connector_security_profiles
			WHERE source_name = p.source_name
		)
		ORDER BY source_name ASC
	`)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list connector security profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []connectorkit.SecurityProfile
	for rows.Next() {
		var p connectorkit.SecurityProfile
		var endpointValidated, pathSanitized, paginationGuarded int
		var credentialsZeroed, enabledRespected, circuitBreaker int
		var hardeningScore float64
		if scanErr := rows.Scan(
			&p.SourceName,
			&endpointValidated,
			&pathSanitized,
			&paginationGuarded,
			&p.TLSMode,
			&credentialsZeroed,
			&enabledRespected,
			&circuitBreaker,
			&p.CredentialPrivilegeTier,
			&hardeningScore,
		); scanErr != nil {
			return nil, fmt.Errorf("scan connector security profile: %w", scanErr)
		}
		p.HardeningScore = float32(hardeningScore)
		p.EndpointValidated = endpointValidated != 0
		p.PathSegmentsSanitized = pathSanitized != 0
		p.PaginationGuarded = paginationGuarded != 0
		p.CredentialsZeroed = credentialsZeroed != 0
		p.EnabledFlagRespected = enabledRespected != 0
		p.CircuitBreakerAttached = circuitBreaker != 0
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connector security profiles: %w", err)
	}
	return out, nil
}

// ConnectorGuardEvent is a single firing of an internal/safenet guard, persisted
// to back the ConnectorGuardEvent ontology class (RFC-0137 4.1.2).
type ConnectorGuardEvent struct {
	OccurredAt     time.Time
	ID             string
	SourceName     string
	GuardEventType string
	BlockedValue   string
	ActionTaken    string
	Severity       string
}

// InsertConnectorGuardEvent appends one guard-event row. blocked_value must be
// pre-truncated/redacted by the caller and must never carry a credential. An
// empty severity defaults to "medium"; a zero OccurredAt defaults to now.
func (s *SQLiteStore) InsertConnectorGuardEvent(ctx context.Context, ev ConnectorGuardEvent) error {
	severity := ev.Severity
	if severity == "" {
		severity = "medium"
	}
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO connector_guard_event (
			id, source_name, guard_event_type, blocked_value, action_taken,
			occurred_at, severity
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.ID,
		ev.SourceName,
		ev.GuardEventType,
		nullStr(ev.BlockedValue),
		ev.ActionTaken,
		occurred.UTC().Format(time.RFC3339Nano),
		severity,
	)
	if err != nil {
		return fmt.Errorf("insert connector guard event %s: %w", ev.ID, err)
	}
	return nil
}

// tlsModeOrDefault coerces an empty TLS mode to the schema default so the
// connector_security_profiles.tls_mode CHECK constraint is always satisfied.
func tlsModeOrDefault(mode string) string {
	if mode == "" {
		return connectorkit.TLSModeSystemCA
	}
	return mode
}

// tierOrDefault coerces an empty credential privilege tier to the schema default.
func tierOrDefault(tier string) string {
	if tier == "" {
		return connectorkit.PrivilegeTierUnknown
	}
	return tier
}
