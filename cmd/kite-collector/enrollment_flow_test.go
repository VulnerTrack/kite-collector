package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/enrollment"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// TestScopedTokenEnrollment_EndToEnd drives the production CLI enrollment
// function against a real HTTP server. The server validates the public PKI
// request contract, signs the submitted CSR, and returns a real certificate
// chain; the assertions then load the exact files the agent would use.
func TestScopedTokenEnrollment_EndToEnd(t *testing.T) {
	const (
		agentCode = "kite-e2e-agent"
		token     = "scoped-token-e2e"
	)

	var requestCount int
	pki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/pki/enroll/token", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Empty(t, r.Header.Get("Authorization"))

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, token, body["token"])
		assert.Equal(t, agentCode, body["agent_code"])
		assert.NotContains(t, body, "client_key")

		response := issueScopedEnrollmentResponse(t, body["csr_pem"])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	t.Cleanup(pki.Close)
	t.Setenv("KITE_PKI_ENDPOINT", pki.URL)

	certsDir := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, runEnrollWithToken(agentCode, token, certsDir))
	assert.Equal(t, 1, requestCount)

	caPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.pem"))
	require.NoError(t, err)
	certPEM, err := os.ReadFile(filepath.Join(certsDir, "agent.pem"))
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, "agent-key.pem"))
	require.NoError(t, err)

	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, agentCode, cert.Subject.CommonName)

	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)
	keyPublic, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PrivateKey).Public())
	require.NoError(t, err)
	assert.Equal(t, certPublic, keyPublic)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)

	keyInfo, err := os.Stat(filepath.Join(certsDir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
}

func TestEnrollCommand_RejectsIncompleteOrAmbiguousCredentials(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "scoped token requires agent code",
			args:    []string{"--enrollment-token", "scoped"},
			wantErr: "--enrollment-token requires --agent-code",
		},
		{
			name:    "operator JWT requires agent code",
			args:    []string{"--token", "jwt"},
			wantErr: "--agent-code and --token must be provided together",
		},
		{
			name:    "agent code requires credential",
			args:    []string{"--agent-code", "kite-agent"},
			wantErr: "--agent-code and --token must be provided together",
		},
		{
			name:    "certificate directory cannot stand alone",
			args:    []string{"--certs-dir", t.TempDir()},
			wantErr: "--certs-dir is only used",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newEnrollCmd()
			cmd.SetArgs(tc.args)
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})

			err := cmd.ExecuteContext(context.Background())

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestOAuthSignIn_EndToEndExchangesPastedCodeWithPKCE(t *testing.T) {
	var tokenForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		tokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"operator-jwt-e2e","token_type":"bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenServer.Close)

	cmd := &cobra.Command{}
	output := &strings.Builder{}
	cmd.SetIn(strings.NewReader("authorization-code-e2e\n"))
	cmd.SetOut(output)
	cfg := enrollment.OAuthConfig{
		Issuer:      tokenServer.URL,
		ClientID:    "kite-cli-e2e",
		RedirectURI: "https://app.example.test/cli-auth",
		Scope:       "openid email",
	}

	token, err := oauthSignIn(cmd, cfg)

	require.NoError(t, err)
	assert.Equal(t, "operator-jwt-e2e", token)
	assert.Contains(t, output.String(), tokenServer.URL+"/oauth/authorize")
	assert.Equal(t, "authorization_code", tokenForm.Get("grant_type"))
	assert.Equal(t, "authorization-code-e2e", tokenForm.Get("code"))
	assert.Equal(t, "kite-cli-e2e", tokenForm.Get("client_id"))
	assert.Equal(t, "https://app.example.test/cli-auth", tokenForm.Get("redirect_uri"))
	assert.GreaterOrEqual(t, len(tokenForm.Get("code_verifier")), 43)
	assert.Empty(t, tokenForm.Get("client_secret"))
}

func TestOAuthSignIn_RejectsMissingConfigAndEmptyCode(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("\n"))
	cmd.SetOut(&strings.Builder{})

	_, err := oauthSignIn(cmd, enrollment.OAuthConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--issuer and --client-id are required")

	cmd.SetIn(strings.NewReader("\n"))
	_, err = oauthSignIn(cmd, enrollment.OAuthConfig{
		Issuer:      "https://auth.example.test",
		ClientID:    "kite-cli",
		RedirectURI: "https://app.example.test/callback",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no code entered")
}

func TestPlatformUnenroll_RemovesOnlyLocalIdentity(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "kite.db")
	identityDir := filepath.Join(root, "identity")
	ctx := context.Background()

	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{DataDir: identityDir})
	require.NoError(t, err)
	require.NoError(t, encStore.Migrate(ctx))
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)
	require.NoError(t, st.UpsertEnrolledIdentity(ctx, sqlite.EnrolledIdentity{
		ApiKeyFingerprint: "fingerprint-before-unenroll",
		ApiKeyWrapped:     []byte("wrapped-before-unenroll"),
		LastEnrolledAt:    time.Now().UTC(),
	}))
	require.NoError(t, encStore.Close())

	credentialSentinel := filepath.Join(root, "agent.pem")
	require.NoError(t, os.WriteFile(credentialSentinel, []byte("keep-me"), 0o600))
	require.NoError(t, runPlatformUnenroll(dbPath, identityDir))

	reopened, err := openSQLiteStore(dbPath, config.IdentityConfig{DataDir: identityDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedStore, ok := reopened.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)
	_, err = reopenedStore.GetEnrolledIdentity(ctx)
	require.Error(t, err)
	kept, err := os.ReadFile(credentialSentinel)
	require.NoError(t, err)
	assert.Equal(t, "keep-me", string(kept), "unenroll must not delete PKI certificate files")
}

func issueScopedEnrollmentResponse(t *testing.T, csrPEM string) map[string]string {
	t.Helper()
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, csrBlock)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Kite Enrollment E2E CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   csr.Subject.CommonName,
			Organization: []string{"00000000-0000-0000-0000-000000000001"},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, csr.PublicKey, caKey)
	require.NoError(t, err)

	return map[string]string{
		"status":              "enrolled",
		"certificate_id":      "cert-e2e",
		"ca_certificate":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		"client_certificate":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		"certificate_expires": leafTemplate.NotAfter.Format(time.RFC3339),
	}
}
