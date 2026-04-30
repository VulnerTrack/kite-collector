package driver

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildSyntheticPE returns a minimal PE32+ file consisting of:
//   - 64-byte DOS stub with e_lfanew at offset 60
//   - "PE\0\0" signature
//   - 20-byte COFF header
//   - 240-byte PE32+ optional header (with at least 5 data dirs)
//   - 16 bytes of "code"
//   - optionally appended 64-byte certificate region
//
// This is sufficient to exercise the Authentihash skip logic deterministically.
func buildSyntheticPE(t *testing.T, withCert bool) []byte {
	t.Helper()

	const peOffset = 64
	const optHeaderSize = 240
	dosStub := make([]byte, peOffset)
	dosStub[0] = 'M'
	dosStub[1] = 'Z'
	binary.LittleEndian.PutUint32(dosStub[60:], peOffset)

	buf := bytes.NewBuffer(nil)
	buf.Write(dosStub)
	buf.WriteString("PE\x00\x00")

	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[16:18], optHeaderSize)
	buf.Write(coff)

	opt := make([]byte, optHeaderSize)
	binary.LittleEndian.PutUint16(opt[0:2], 0x20b) // PE32+
	for i := range opt[64:68] {
		opt[64+i] = 0x55 // recognisable garbage in CheckSum
	}
	const dataDirOffset = 112
	const certEntryIndex = 4
	certEntry := opt[dataDirOffset+certEntryIndex*8 : dataDirOffset+certEntryIndex*8+8]
	buf.Write(opt)

	codeStart := buf.Len()
	code := []byte("HELLOPECONTENT12")
	buf.Write(code)

	if withCert {
		bufLen := buf.Len()
		require.LessOrEqual(t, bufLen, int(^uint32(0)), "synthetic PE must fit in uint32")
		certVA := uint32(bufLen) //nolint:gosec // bounded above
		certSize := uint32(64)
		binary.LittleEndian.PutUint32(certEntry[0:4], certVA)
		binary.LittleEndian.PutUint32(certEntry[4:8], certSize)

		// rewrite the section so the embedded certEntry is current
		copy(opt[dataDirOffset+certEntryIndex*8:], certEntry)
		final := buf.Bytes()
		copy(final[peOffset+4+20:peOffset+4+20+optHeaderSize], opt)

		certRegion := bytes.Repeat([]byte{0xAA}, int(certSize))
		buf.Write(certRegion)
	}
	_ = codeStart
	return buf.Bytes()
}

func TestAuthenticodeHash_RoundtripExcludesCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	withCert := buildSyntheticPE(t, true)
	withoutCert := buildSyntheticPE(t, false)

	pathA := filepath.Join(dir, "withcert.bin")
	pathB := filepath.Join(dir, "nocert.bin")
	require.NoError(t, os.WriteFile(pathA, withCert, 0o600))
	require.NoError(t, os.WriteFile(pathB, withoutCert, 0o600))

	hashA, err := AuthenticodeHash(pathA)
	require.NoError(t, err)
	hashB, err := AuthenticodeHash(pathB)
	require.NoError(t, err)
	assert.Equal(t, hashA, hashB,
		"file with appended cert region must hash identically to one without")
}

func TestAuthenticodeHash_DifferentChecksumSameDigest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pe := buildSyntheticPE(t, false)
	pathA := filepath.Join(dir, "a.bin")
	pathB := filepath.Join(dir, "b.bin")
	require.NoError(t, os.WriteFile(pathA, pe, 0o600))

	mutated := append([]byte{}, pe...)
	const peOffset = 64
	const optHeaderOffset = peOffset + 4 + 20
	const checksumOff = optHeaderOffset + 64
	for i := 0; i < 4; i++ {
		mutated[checksumOff+i] = byte(0xFF - i)
	}
	require.NoError(t, os.WriteFile(pathB, mutated, 0o600))

	hashA, err := AuthenticodeHash(pathA)
	require.NoError(t, err)
	hashB, err := AuthenticodeHash(pathB)
	require.NoError(t, err)
	assert.Equal(t, hashA, hashB,
		"changing only the CheckSum field must not change the Authentihash")
}

func TestAuthenticodeHash_DifferingCodeMutatesDigest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pe := buildSyntheticPE(t, false)

	pathA := filepath.Join(dir, "a.bin")
	pathB := filepath.Join(dir, "b.bin")
	require.NoError(t, os.WriteFile(pathA, pe, 0o600))

	mutated := append([]byte{}, pe...)
	mutated[len(mutated)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(pathB, mutated, 0o600))

	hashA, err := AuthenticodeHash(pathA)
	require.NoError(t, err)
	hashB, err := AuthenticodeHash(pathB)
	require.NoError(t, err)
	assert.NotEqual(t, hashA, hashB, "code-byte changes must alter the digest")
}

func TestAuthenticodeHash_NotPEReturnsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bogus := filepath.Join(dir, "bogus.bin")
	require.NoError(t, os.WriteFile(bogus, []byte("definitely not a PE"), 0o600))
	_, err := AuthenticodeHash(bogus)
	require.Error(t, err)
}

func TestAuthenticodeHashSHA1_Works(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pe := buildSyntheticPE(t, false)
	path := filepath.Join(dir, "x.bin")
	require.NoError(t, os.WriteFile(path, pe, 0o600))
	h, err := AuthenticodeHashSHA1(path)
	require.NoError(t, err)
	assert.Len(t, h, 40, "sha1 hex digest is 40 chars")
	_, err = hex.DecodeString(h)
	require.NoError(t, err)
}

func TestAuthenticodeHash_DigestMatchesManualSHA256(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pe := buildSyntheticPE(t, false)
	path := filepath.Join(dir, "manual.bin")
	require.NoError(t, os.WriteFile(path, pe, 0o600))

	got, err := AuthenticodeHash(path)
	require.NoError(t, err)

	// Recompute manually: skip CheckSum (4 bytes) + Cert dir entry (8 bytes).
	const peOffset = 64
	const optHeaderOffset = peOffset + 4 + 20
	const checksumOff = optHeaderOffset + 64
	const certDirOff = optHeaderOffset + 112 + 4*8
	skipBytes := func(b []byte) []byte {
		out := make([]byte, 0, len(b))
		out = append(out, b[:checksumOff]...)
		out = append(out, b[checksumOff+4:certDirOff]...)
		out = append(out, b[certDirOff+8:]...)
		return out
	}
	expectedRaw := skipBytes(pe)
	sum := sha256.Sum256(expectedRaw)
	assert.Equal(t, hex.EncodeToString(sum[:]), got)
}
