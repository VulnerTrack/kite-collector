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

const testTenant = "11111111-1111-4111-8111-111111111111"

func writeCert(t *testing.T, org ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kite-agent", Organization: org},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "agent.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestTenantFromCertFile_ReadsUUIDOrganization(t *testing.T) {
	assert.Equal(t, testTenant, TenantFromCertFile(writeCert(t, testTenant)))
}

func TestTenantFromCertFile_EmptyWhenNoOrg(t *testing.T) {
	assert.Empty(t, TenantFromCertFile(writeCert(t)))
}

func TestTenantFromCertFile_EmptyWhenOrgNotUUID(t *testing.T) {
	assert.Empty(t, TenantFromCertFile(writeCert(t, "acme-corp")))
}

func TestTenantFromCertFile_EmptyWhenMissingFile(t *testing.T) {
	assert.Empty(t, TenantFromCertFile("/no/such/cert.pem"))
	assert.Empty(t, TenantFromCertFile(""))
}

func TestResolveTenantID_CertWinsOverEnv(t *testing.T) {
	// A valid cert tenant is authoritative and must not be overridden by env.
	certPath := writeCert(t, testTenant)
	assert.Equal(t, testTenant,
		ResolveTenantID(certPath, "22222222-2222-4222-8222-222222222222"))
}

func TestResolveTenantID_FallsBackToEnv(t *testing.T) {
	// No cert tenant -> env fallback (pre-enrollment / non-mTLS).
	assert.Equal(t, "env-tenant", ResolveTenantID(writeCert(t), "env-tenant"))
	assert.Empty(t, ResolveTenantID("", ""))
}

// PKI can stamp the human organization name as an additional non-UUID
// Organization value alongside the tenant UUID; both halves must come
// back regardless of order, and certs predating name stamping yield the
// UUID alone.
func TestTenantOrgFromCertFile_UUIDAndName(t *testing.T) {
	id, name := TenantOrgFromCertFile(writeCert(t, testTenant, "Acme Corp"))
	assert.Equal(t, testTenant, id)
	assert.Equal(t, "Acme Corp", name)

	id, name = TenantOrgFromCertFile(writeCert(t, "Acme Corp", testTenant))
	assert.Equal(t, testTenant, id, "order of O values must not matter")
	assert.Equal(t, "Acme Corp", name)
}

func TestTenantOrgFromCertFile_UUIDOnlyLegacyCert(t *testing.T) {
	id, name := TenantOrgFromCertFile(writeCert(t, testTenant))
	assert.Equal(t, testTenant, id)
	assert.Empty(t, name, "pre-org-name certs have no name to show")
}

func TestTenantOrgFromCertFile_Absent(t *testing.T) {
	id, name := TenantOrgFromCertFile(writeCert(t))
	assert.Empty(t, id)
	assert.Empty(t, name)
	id, name = TenantOrgFromCertFile("/no/such/cert.pem")
	assert.Empty(t, id)
	assert.Empty(t, name)
}
