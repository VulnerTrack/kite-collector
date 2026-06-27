package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrCreate_GeneratesNewIdentity(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	id, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)
	require.NotNil(t, id)

	assert.NotEqual(t, [16]byte{}, id.AgentID)
	assert.Len(t, id.PublicKey, ed25519.PublicKeySize)
	assert.Len(t, id.PrivateKey, ed25519.PrivateKeySize)

	// File must exist.
	_, err = os.Stat(filepath.Join(dir, "identity.json"))
	require.NoError(t, err)
}

func TestLoadOrCreate_LoadsExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	id1, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)

	id2, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)

	assert.Equal(t, id1.AgentID, id2.AgentID)
	assert.Equal(t, id1.PublicKey, id2.PublicKey)
}

func TestIdentity_Fingerprint(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	fp := id.Fingerprint()
	assert.Contains(t, fp, "sha256:")
	assert.Len(t, fp, 7+64) // "sha256:" + 64 hex chars
}

func TestIdentity_JSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	data, err := json.Marshal(id)
	require.NoError(t, err)

	var id2 Identity
	require.NoError(t, json.Unmarshal(data, &id2))

	assert.Equal(t, id.AgentID, id2.AgentID)
	assert.Equal(t, id.PublicKey, id2.PublicKey)
	assert.Equal(t, id.PrivateKey, id2.PrivateKey)
}

func TestLoadOrCreate_RejectsInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission check not applicable on Windows")
	}

	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	// Make the file world-readable.
	idPath := filepath.Join(dir, "identity.json")
	require.NoError(t, os.Chmod(idPath, 0o644))

	_, err = LoadOrCreate(dir, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure permissions")

	// Verify we can still use the originally loaded identity.
	assert.NotNil(t, id)
}

func TestDeriveStorageKey_Returns32Bytes(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	key, err := id.DeriveStorageKey()
	require.NoError(t, err)
	assert.Len(t, key, 32, "AES-256 key must be 32 bytes")
}

func TestDeriveStorageKey_Deterministic(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	key1, err := id.DeriveStorageKey()
	require.NoError(t, err)

	key2, err := id.DeriveStorageKey()
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "same identity must derive the same key")
}

func TestDeriveStorageKey_DifferentIdentitiesProduceDifferentKeys(t *testing.T) {
	id1, err := LoadOrCreate(t.TempDir(), slog.Default())
	require.NoError(t, err)

	id2, err := LoadOrCreate(t.TempDir(), slog.Default())
	require.NoError(t, err)

	key1, err := id1.DeriveStorageKey()
	require.NoError(t, err)
	key2, err := id2.DeriveStorageKey()
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different identities must derive different keys")
}

func TestDeriveStorageKey_SurvivesReload(t *testing.T) {
	dir := t.TempDir()

	id1, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	key1, err := id1.DeriveStorageKey()
	require.NoError(t, err)

	// Reload identity from disk.
	id2, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	key2, err := id2.DeriveStorageKey()
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "reloaded identity must derive the same key")
}

func TestIdentity_SignVerify(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir(), slog.Default())
	require.NoError(t, err)

	msg := []byte("probe.heartbeat|agent.firewall|ok|42")
	sig := id.Sign(msg)
	require.Len(t, sig, ed25519.SignatureSize)

	assert.True(t, Verify(id.PublicKey, msg, sig), "valid signature must verify")

	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0xFF
	assert.False(t, Verify(id.PublicKey, tampered, sig), "tampered message must not verify")

	badSig := append([]byte{}, sig...)
	badSig[0] ^= 0xFF
	assert.False(t, Verify(id.PublicKey, msg, badSig), "tampered signature must not verify")

	assert.False(t, Verify(nil, msg, sig), "nil pubkey must not verify")
	assert.False(t, Verify(id.PublicKey, msg, sig[:10]), "short signature must not verify")
}

func TestComputeBinaryHash_StableAndPrefixed(t *testing.T) {
	h1, err := ComputeBinaryHash()
	require.NoError(t, err)
	require.True(t, len(h1) > len("sha256:"))
	assert.Contains(t, h1, "sha256:")

	h2, err := ComputeBinaryHash()
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "hash must be deterministic across calls within a single run")
}

func TestLoadOrCreate_StampsExpectedBinaryHashOnFirstBoot(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	// First boot must compute and persist the hash so the next launch has a
	// reference value to compare against.
	require.NotEmpty(t, id.BinaryHash, "first boot must compute live binary hash")
	require.NotEmpty(t, id.ExpectedBinaryHash, "first boot must stamp expected hash")
	assert.Equal(t, id.BinaryHash, id.ExpectedBinaryHash)

	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), "expected_binary_hash")
}

func TestLoadOrCreate_StampsExpectedBinaryHashOnLegacyFile(t *testing.T) {
	// Simulate an identity.json written by a pre-v1.1 build (no
	// expected_binary_hash field): the next load must stamp it without
	// rotating the keypair. Generate via current code, then rewrite the
	// file in the legacy three-field shape derived from the live keys.
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")

	first, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	originalAgentID := first.AgentID
	originalPub := first.PublicKey

	// Rewrite without expected_binary_hash, using base64 keys exactly as
	// pre-v1.1 MarshalJSON would have produced.
	stripped := map[string]string{
		"public_key":  base64.StdEncoding.EncodeToString(first.PublicKey),
		"private_key": base64.StdEncoding.EncodeToString(first.PrivateKey),
		"agent_id":    first.AgentID.String(),
	}
	data, err := json.Marshal(stripped)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(idPath, data, 0o600))

	reloaded, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	assert.Equal(t, originalAgentID, reloaded.AgentID, "AgentID must not rotate")
	assert.Equal(t, originalPub, reloaded.PublicKey, "PublicKey must not rotate")
	assert.NotEmpty(t, reloaded.ExpectedBinaryHash, "stamp-on-load must populate expected hash")
	assert.Equal(t, reloaded.BinaryHash, reloaded.ExpectedBinaryHash)

	// Persisted on disk too.
	raw, err := os.ReadFile(idPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "expected_binary_hash")
}
