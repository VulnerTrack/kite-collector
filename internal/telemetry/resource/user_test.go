package resource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testUserID = "33333333-3333-4333-8333-333333333333"
	testEmail  = "operator@example.com"
)

func writeUserCert(t *testing.T, ou []string, emails []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "kite-agent", OrganizationalUnit: ou},
		EmailAddresses: emails,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "agent.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestUserFromCertFile_ReadsOUAndEmailSAN(t *testing.T) {
	path := writeUserCert(t, []string{testUserID}, []string{testEmail})
	userID, email := UserFromCertFile(path)
	assert.Equal(t, testUserID, userID)
	assert.Equal(t, testEmail, email)
}

func TestUserFromCertFile_EmptyWhenNotStamped(t *testing.T) {
	// Certificates issued before user stamping carry neither OU nor email.
	userID, email := UserFromCertFile(writeUserCert(t, nil, nil))
	assert.Empty(t, userID)
	assert.Empty(t, email)
}

func TestUserFromCertFile_RejectsNonUUIDOU(t *testing.T) {
	// An OU repurposed for something else must not be mistaken for a user id;
	// the email is still surfaced independently.
	userID, email := UserFromCertFile(
		writeUserCert(t, []string{"platform-team"}, []string{testEmail}))
	assert.Empty(t, userID)
	assert.Equal(t, testEmail, email)
}

func TestUserFromCertFile_EmptyWhenMissingFile(t *testing.T) {
	userID, email := UserFromCertFile("/no/such/cert.pem")
	assert.Empty(t, userID)
	assert.Empty(t, email)
	userID, email = UserFromCertFile("")
	assert.Empty(t, userID)
	assert.Empty(t, email)
}

func TestUserFromCertPEM_GarbageInput(t *testing.T) {
	userID, email := UserFromCertPEM([]byte("not a pem"))
	assert.Empty(t, userID)
	assert.Empty(t, email)
}
