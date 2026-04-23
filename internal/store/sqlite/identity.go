package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// ErrNoIdentity is returned by GetEnrolledIdentity when no row is present.
var ErrNoIdentity = errors.New("no enrolled identity")

// EnrolledIdentity is the singleton row of the enrolled_identity table.
// It holds the platform endpoint plus the AEAD-wrapped API key blob;
// callers must never log or echo the plaintext key that lives inside
// ApiKeyWrapped.
type EnrolledIdentity struct {
	FirstEnrolledAt   time.Time
	LastEnrolledAt    time.Time
	LastCheckPassedAt *time.Time
	LastCheckFailedAt *time.Time
	PlatformEndpoint  string
	ApiKeyFingerprint string
	ApiKeyWrapped     []byte
}

// ProbeResultRecord is a persisted connection-check probe outcome.
type ProbeResultRecord struct {
	CheckedAt  time.Time
	ProbeRunID string
	ProbeName  string
	Result     string
	Diagnostic string
	LatencyMS  int64
}

// APIKeyFingerprint computes the canonical sha256[:16] hex fingerprint used
// to identify an API key across dashboard responses, logs, and probe 4
// (auth-echo). The first eight hex characters form the short form rendered
// in HTML; the full string is the database identity.
func APIKeyFingerprint(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:32]
}

// AEADWrap seals plaintext with AES-256-GCM and a random 12-byte nonce.
// The returned blob is [nonce][ciphertext||tag] — the exact shape written
// to enrolled_identity.api_key_wrapped. key MUST be 32 bytes.
func AEADWrap(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aead wrap: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead wrap: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead wrap: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aead wrap: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// AEADUnwrap is the inverse of AEADWrap. It verifies the GCM tag and
// returns the plaintext or a typed error on any authentication failure,
// making deliberate bit-flips on api_key_wrapped detectable in tests.
func AEADUnwrap(key, wrapped []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aead unwrap: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead unwrap: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead unwrap: new gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("aead unwrap: ciphertext too short")
	}
	nonce, ct := wrapped[:nonceSize], wrapped[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aead unwrap: authentication failed: %w", err)
	}
	return pt, nil
}

// UpsertEnrolledIdentity persists the singleton enrolled_identity row.
// If a row already exists, first_enrolled_at is preserved while all other
// columns are overwritten with the supplied values — this matches the
// idempotent-enroll contract from R6: re-POSTing the same pair refreshes
// last_enrolled_at and leaves history untouched.
func (s *SQLiteStore) UpsertEnrolledIdentity(ctx context.Context, id EnrolledIdentity) error {
	now := id.LastEnrolledAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	first := id.FirstEnrolledAt
	if first.IsZero() {
		first = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO enrolled_identity (
			id, platform_endpoint, api_key_fingerprint, api_key_wrapped,
			first_enrolled_at, last_enrolled_at
		) VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			platform_endpoint    = excluded.platform_endpoint,
			api_key_fingerprint  = excluded.api_key_fingerprint,
			api_key_wrapped      = excluded.api_key_wrapped,
			last_enrolled_at     = excluded.last_enrolled_at
	`,
		id.PlatformEndpoint,
		id.ApiKeyFingerprint,
		id.ApiKeyWrapped,
		first.UnixMilli(),
		now.UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("upsert enrolled_identity: %w", err)
	}
	return nil
}

// GetEnrolledIdentity returns the singleton row or ErrNoIdentity when the
// collector has never been enrolled.
func (s *SQLiteStore) GetEnrolledIdentity(ctx context.Context) (*EnrolledIdentity, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT platform_endpoint, api_key_fingerprint, api_key_wrapped,
		       first_enrolled_at, last_enrolled_at,
		       last_check_passed_at, last_check_failed_at
		FROM enrolled_identity WHERE id = 1
	`)
	var (
		id              EnrolledIdentity
		firstMS, lastMS int64
		passedMS        sql.NullInt64
		failedMS        sql.NullInt64
	)
	err := row.Scan(
		&id.PlatformEndpoint,
		&id.ApiKeyFingerprint,
		&id.ApiKeyWrapped,
		&firstMS,
		&lastMS,
		&passedMS,
		&failedMS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, ErrNoIdentity
		}
		return nil, fmt.Errorf("get enrolled_identity: %w", err)
	}
	id.FirstEnrolledAt = time.UnixMilli(firstMS).UTC()
	id.LastEnrolledAt = time.UnixMilli(lastMS).UTC()
	if passedMS.Valid {
		t := time.UnixMilli(passedMS.Int64).UTC()
		id.LastCheckPassedAt = &t
	}
	if failedMS.Valid {
		t := time.UnixMilli(failedMS.Int64).UTC()
		id.LastCheckFailedAt = &t
	}
	return &id, nil
}

// DeleteEnrolledIdentity removes the singleton row. Primarily intended for
// tests and operator-driven reset flows (not wired into the UI yet).
func (s *SQLiteStore) DeleteEnrolledIdentity(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM enrolled_identity WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("delete enrolled_identity: %w", err)
	}
	return nil
}

// UpdateIdentityCheckStamp stamps last_check_passed_at or last_check_failed_at
// on the singleton identity row. Callers pass exactly one of passed/failed —
// the other is written as NULL unchanged (via COALESCE) so partial updates
// don't clobber the opposite column.
func (s *SQLiteStore) UpdateIdentityCheckStamp(ctx context.Context, passed, failed *time.Time) error {
	var passedArg, failedArg sql.NullInt64
	if passed != nil {
		passedArg = sql.NullInt64{Int64: passed.UnixMilli(), Valid: true}
	}
	if failed != nil {
		failedArg = sql.NullInt64{Int64: failed.UnixMilli(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE enrolled_identity
		   SET last_check_passed_at = COALESCE(?, last_check_passed_at),
		       last_check_failed_at = COALESCE(?, last_check_failed_at)
		 WHERE id = 1
	`, passedArg, failedArg)
	if err != nil {
		return fmt.Errorf("update identity check stamp: %w", err)
	}
	return nil
}

// InsertProbeResult appends one probe outcome to probe_result. The capping
// trigger in the migration discards rows beyond the most recent 100 so the
// table never grows unbounded.
func (s *SQLiteStore) InsertProbeResult(ctx context.Context, r ProbeResultRecord) error {
	if r.ProbeRunID == "" {
		r.ProbeRunID = uuid.Must(uuid.NewV7()).String()
	}
	if r.CheckedAt.IsZero() {
		r.CheckedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO probe_result (
			probe_run_id, probe_name, result, latency_ms, diagnostic, checked_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`,
		r.ProbeRunID,
		r.ProbeName,
		r.Result,
		r.LatencyMS,
		nullStr(r.Diagnostic),
		r.CheckedAt.UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("insert probe_result: %w", err)
	}
	return nil
}

// ListProbeResults returns the most-recent probe outcomes ordered by
// checked_at DESC. limit ≤ 0 defaults to 20 (the support-bundle size per
// RFC-0112 R11). A missing probe_result table yields (nil, nil) so a fresh
// DB does not 500 the fragment.
func (s *SQLiteStore) ListProbeResults(ctx context.Context, limit int) ([]ProbeResultRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT probe_run_id, probe_name, result, latency_ms, diagnostic, checked_at
		FROM probe_result ORDER BY checked_at DESC, probe_run_id DESC LIMIT ?
	`, limit)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list probe_result: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ProbeResultRecord
	for rows.Next() {
		var (
			rec        ProbeResultRecord
			diagnostic sql.NullString
			checkedMS  int64
		)
		if err := rows.Scan(
			&rec.ProbeRunID,
			&rec.ProbeName,
			&rec.Result,
			&rec.LatencyMS,
			&diagnostic,
			&checkedMS,
		); err != nil {
			return nil, fmt.Errorf("scan probe_result row: %w", err)
		}
		rec.Diagnostic = diagnostic.String
		rec.CheckedAt = time.UnixMilli(checkedMS).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate probe_result rows: %w", err)
	}
	return out, nil
}
