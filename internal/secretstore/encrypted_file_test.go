package secretstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptedFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, err := NewEncryptedFile(path, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	require.NoError(t, store.Put("ldap/password", []byte("secret-value")))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "secret-value")
	got, err := store.Get("ldap/password")
	require.NoError(t, err)
	require.Equal(t, []byte("secret-value"), got)
	require.NoError(t, store.Delete("ldap/password"))
	_, err = store.Get("ldap/password")
	require.True(t, errors.Is(err, ErrNotFound))
}

func TestEncryptedFileStoreWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	first, err := NewEncryptedFile(path, bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	require.NoError(t, first.Put("name", []byte("value")))
	second, err := NewEncryptedFile(path, bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	_, err = second.Get("name")
	require.Error(t, err)
}
