package safenet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeCursor(t *testing.T) {
	t.Run("accepts standard base64", func(t *testing.T) {
		got, err := SanitizeCursor("eyJpZCI6IjEyMyJ9")
		require.NoError(t, err)
		assert.Equal(t, "eyJpZCI6IjEyMyJ9", got)
	})

	t.Run("accepts base64 with padding", func(t *testing.T) {
		got, err := SanitizeCursor("YWJjZA==")
		require.NoError(t, err)
		assert.Equal(t, "YWJjZA==", got)
	})

	t.Run("accepts URL-safe base64", func(t *testing.T) {
		got, err := SanitizeCursor("a-b_c-d-eyJ4IjoxfQ")
		require.NoError(t, err)
		assert.Equal(t, "a-b_c-d-eyJ4IjoxfQ", got)
	})

	t.Run("accepts JWT-shaped opaque cursor", func(t *testing.T) {
		got, err := SanitizeCursor("h1.h2.h3")
		require.NoError(t, err)
		assert.Equal(t, "h1.h2.h3", got)
	})

	t.Run("accepts opaque hex cursor", func(t *testing.T) {
		got, err := SanitizeCursor("abc123def456")
		require.NoError(t, err)
		assert.Equal(t, "abc123def456", got)
	})

	t.Run("accepts traversal-shaped string (defense is contextual, not lexical)", func(t *testing.T) {
		got, err := SanitizeCursor("../../../admin")
		require.NoError(t, err)
		assert.Equal(t, "../../../admin", got)
	})

	t.Run("accepts scheme-shaped string (defense is contextual, not lexical)", func(t *testing.T) {
		got, err := SanitizeCursor("https://evil.com/admin")
		require.NoError(t, err)
		assert.Equal(t, "https://evil.com/admin", got)
	})

	t.Run("rejects fragment marker", func(t *testing.T) {
		_, err := SanitizeCursor("abc#frag")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})

	t.Run("rejects percent-encoding", func(t *testing.T) {
		_, err := SanitizeCursor("abc%2F")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})

	t.Run("rejects query string", func(t *testing.T) {
		_, err := SanitizeCursor("page?token=x&admin=true")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})

	t.Run("rejects whitespace", func(t *testing.T) {
		_, err := SanitizeCursor("a b c")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})

	t.Run("rejects newlines", func(t *testing.T) {
		_, err := SanitizeCursor("abc\ndef")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})

	t.Run("rejects empty cursor", func(t *testing.T) {
		_, err := SanitizeCursor("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("rejects oversized cursor", func(t *testing.T) {
		oversized := strings.Repeat("a", MaxCursorLength+1)
		_, err := SanitizeCursor(oversized)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("accepts cursor at exact max length", func(t *testing.T) {
		boundary := strings.Repeat("a", MaxCursorLength)
		got, err := SanitizeCursor(boundary)
		require.NoError(t, err)
		assert.Equal(t, boundary, got)
	})

	t.Run("rejects null byte", func(t *testing.T) {
		_, err := SanitizeCursor("abc\x00def")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed character")
	})
}
