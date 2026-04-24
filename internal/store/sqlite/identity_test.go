package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAEADWrapUnwrap_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := []byte("sk-platform-live-ABCDEF0123456789")
	wrapped, err := AEADWrap(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, wrapped, "wrap must produce ciphertext distinct from plaintext")

	got, err := AEADUnwrap(key, wrapped)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestAEADUnwrap_DetectsBitFlip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	wrapped, err := AEADWrap(key, []byte("api-key"))
	require.NoError(t, err)

	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0x01 // flip the last byte of the GCM tag

	_, err = AEADUnwrap(key, tampered)
	assert.Error(t, err, "bit-flip in the AEAD tag must be detected")
}

func TestAEADWrap_RejectsShortKey(t *testing.T) {
	_, err := AEADWrap(make([]byte, 16), []byte("x"))
	assert.Error(t, err)
}

func TestAPIKeyFingerprint_Stable(t *testing.T) {
	a := APIKeyFingerprint("sk-abc")
	b := APIKeyFingerprint("sk-abc")
	c := APIKeyFingerprint("sk-different")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 32, "fingerprint is sha256 truncated to 32 hex chars")
}

func TestUpsertGetEnrolledIdentity(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := st.GetEnrolledIdentity(ctx)
	assert.ErrorIs(t, err, ErrNoIdentity)

	id := EnrolledIdentity{
		ApiKeyFingerprint: APIKeyFingerprint("sk-abc"),
		ApiKeyWrapped:     []byte("wrapped-blob"),
	}
	require.NoError(t, st.UpsertEnrolledIdentity(ctx, id))

	got, err := st.GetEnrolledIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, id.ApiKeyFingerprint, got.ApiKeyFingerprint)
	assert.Equal(t, id.ApiKeyWrapped, got.ApiKeyWrapped)
	assert.False(t, got.FirstEnrolledAt.IsZero())
	assert.Equal(t, got.FirstEnrolledAt, got.LastEnrolledAt, "fresh row: first == last")
}

func TestUpsertEnrolledIdentity_IsIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	id := EnrolledIdentity{
		ApiKeyFingerprint: APIKeyFingerprint("sk-abc"),
		ApiKeyWrapped:     []byte("blob-1"),
	}
	require.NoError(t, st.UpsertEnrolledIdentity(ctx, id))
	first, err := st.GetEnrolledIdentity(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	// Re-upsert with a new wrapped blob to simulate a re-enroll.
	id.ApiKeyWrapped = []byte("blob-2")
	id.LastEnrolledAt = time.Now().UTC()
	require.NoError(t, st.UpsertEnrolledIdentity(ctx, id))

	second, err := st.GetEnrolledIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, first.FirstEnrolledAt.UnixMilli(), second.FirstEnrolledAt.UnixMilli(),
		"first_enrolled_at must be preserved on re-enroll")
	assert.GreaterOrEqual(t, second.LastEnrolledAt.UnixMilli(), first.LastEnrolledAt.UnixMilli(),
		"last_enrolled_at must not regress")
	assert.Equal(t, []byte("blob-2"), second.ApiKeyWrapped)
}

func TestInsertAndListProbeResults(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	for i, name := range []string{"dns", "tls", "reach", "auth", "clock", "otlp"} {
		require.NoError(t, st.InsertProbeResult(ctx, ProbeResultRecord{
			ProbeName:  name,
			Result:     "pass",
			LatencyMS:  int64(10 + i),
			Diagnostic: "ok",
		}))
	}

	results, err := st.ListProbeResults(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, results, 6)
}

func TestInsertProbeResult_CapsAt100(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Insert 120 rows; the AFTER INSERT trigger should cap the table at 100.
	now := time.Now().UTC()
	for i := 0; i < 120; i++ {
		require.NoError(t, st.InsertProbeResult(ctx, ProbeResultRecord{
			ProbeName: "dns",
			Result:    "pass",
			LatencyMS: int64(i),
			CheckedAt: now.Add(time.Duration(i) * time.Millisecond),
		}))
	}

	results, err := st.ListProbeResults(ctx, 500)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(results), 100, "trigger must cap probe_result at 100 rows")
}

func TestUpdateIdentityCheckStamp(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, st.UpsertEnrolledIdentity(ctx, EnrolledIdentity{
		ApiKeyFingerprint: APIKeyFingerprint("k"),
		ApiKeyWrapped:     []byte("w"),
	}))

	now := time.Now().UTC()
	require.NoError(t, st.UpdateIdentityCheckStamp(ctx, &now, nil))
	got, err := st.GetEnrolledIdentity(ctx)
	require.NoError(t, err)
	require.NotNil(t, got.LastCheckPassedAt)
	assert.Nil(t, got.LastCheckFailedAt)

	// Now stamp a failure; the previous pass timestamp must not be erased.
	fail := now.Add(time.Second)
	require.NoError(t, st.UpdateIdentityCheckStamp(ctx, nil, &fail))
	got, err = st.GetEnrolledIdentity(ctx)
	require.NoError(t, err)
	require.NotNil(t, got.LastCheckPassedAt)
	require.NotNil(t, got.LastCheckFailedAt)
}
