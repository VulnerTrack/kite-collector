package grpcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// In-memory test PKI — generates CA, server, and client certs on the fly.
// ---------------------------------------------------------------------------

type testPKI struct {
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caCertPEM  []byte
	srvCertPEM []byte
	srvKeyPEM  []byte
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server certificate.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	require.NoError(t, err)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	return &testPKI{
		caCert:     caCert,
		caKey:      caKey,
		caCertPEM:  caPEM,
		srvCertPEM: srvCertPEM,
		srvKeyPEM:  srvKeyPEM,
	}
}

// issueClientCert creates a client certificate signed by the test CA.
func (p *testPKI) issueClientCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &clientKey.PublicKey, p.caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writePEM writes PEM data to a temp-dir file and returns the path.
func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// ---------------------------------------------------------------------------
// Enrolling gRPC server — extends Server with a real Enroll implementation
// that issues client certs from the test CA.
// ---------------------------------------------------------------------------

type enrollingServer struct {
	*Server
	pki *testPKI
}

func (e *enrollingServer) Enroll(_ context.Context, req *kitev1.EnrollRequest) (*kitev1.EnrollResponse, error) {
	if req.EnrollmentToken == "" {
		return nil, status.Errorf(codes.Unauthenticated, "enrollment token required")
	}
	if req.EnrollmentToken != "valid-token" {
		return nil, status.Errorf(codes.PermissionDenied, "invalid enrollment token")
	}

	// Issue a client certificate signed by the test CA.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}
	expiry := time.Now().Add(24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: req.AgentId, Organization: []string{"kite-collector"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     expiry,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, e.pki.caCert, &clientKey.PublicKey, e.pki.caKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &kitev1.EnrollResponse{
		Status:               "enrolled",
		CaCertificate:        e.pki.caCertPEM,
		ClientCertificate:    certPEM,
		ClientKeyEncrypted:   keyPEM,
		CertificateExpiresAt: expiry.Unix(),
	}, nil
}

// ---------------------------------------------------------------------------
// Minimal in-memory store satisfying store.Store for server construction.
// ---------------------------------------------------------------------------

type memStore struct{}

func (m *memStore) UpsertAsset(_ context.Context, _ model.Asset) error { return nil }
func (m *memStore) UpsertAssets(_ context.Context, a []model.Asset) (int, int, error) {
	return len(a), 0, nil
}

func (m *memStore) GetAssetByID(_ context.Context, _ uuid.UUID) (*model.Asset, error) {
	return nil, store.ErrNotFound
}

func (m *memStore) GetAssetByNaturalKey(_ context.Context, _ string) (*model.Asset, error) {
	return nil, nil
}

func (m *memStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	return nil, nil
}

func (m *memStore) GetStaleAssets(_ context.Context, _ time.Duration) ([]model.Asset, error) {
	return nil, nil
}
func (m *memStore) InsertEvent(_ context.Context, _ model.AssetEvent) error { return nil }
func (m *memStore) InsertEvents(_ context.Context, _ []model.AssetEvent) error {
	return nil
}

func (m *memStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	return nil, nil
}
func (m *memStore) CreateScanRun(_ context.Context, _ model.ScanRun) error { return nil }
func (m *memStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return nil
}
func (m *memStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) { return nil, nil }

func (m *memStore) GetScanRun(_ context.Context, _ uuid.UUID) (*model.ScanRun, error) {
	return nil, store.ErrNotFound
}

func (m *memStore) MarkScanCancelRequested(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return store.ErrNotFound
}

func (m *memStore) UpsertSoftware(_ context.Context, _ uuid.UUID, _ []model.InstalledSoftware) error {
	return nil
}

func (m *memStore) ListSoftware(_ context.Context, _ uuid.UUID) ([]model.InstalledSoftware, error) {
	return nil, nil
}
func (m *memStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error { return nil }
func (m *memStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (m *memStore) InsertPostureAssessments(_ context.Context, _ []model.PostureAssessment) error {
	return nil
}

func (m *memStore) ListPostureAssessments(_ context.Context, _ store.PostureFilter) ([]model.PostureAssessment, error) {
	return nil, nil
}

func (m *memStore) InsertRuntimeIncident(_ context.Context, _ model.RuntimeIncident) error {
	return nil
}

func (m *memStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	return nil, nil
}
func (m *memStore) Migrate(_ context.Context) error { return nil }
func (m *memStore) Close() error                    { return nil }

func (m *memStore) ListContentTables(_ context.Context) ([]store.TableSchema, error) {
	return nil, nil
}

func (m *memStore) DescribeTable(_ context.Context, _ string) (*store.TableSchema, error) {
	return nil, store.ErrUnknownTable
}

func (m *memStore) ListRows(_ context.Context, _ store.RowsFilter) ([]store.Row, int64, error) {
	return nil, 0, store.ErrUnknownTable
}

func (m *memStore) GetRowReport(_ context.Context, _ string, _ map[string]string) (*store.RowReport, error) {
	return nil, store.ErrUnknownTable
}

// ---------------------------------------------------------------------------
// Helper: start an mTLS gRPC server with the enrolling service.
// ---------------------------------------------------------------------------

// startTestServer starts a gRPC server with mTLS on a random localhost port.
// It returns the server address and a cleanup function. The Enroll RPC issues
// real client certificates from the test CA so the full enrollment→connect
// round-trip can be exercised.
func startTestServer(t *testing.T, pki *testPKI) (addr string, cleanup func()) {
	t.Helper()

	dir := t.TempDir()
	caPath := writePEM(t, dir, "ca.pem", pki.caCertPEM)
	certPath := writePEM(t, dir, "server.pem", pki.srvCertPEM)
	keyPath := writePEM(t, dir, "server-key.pem", pki.srvKeyPEM)

	// Build server-side mTLS config.
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(pki.caCertPEM))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven, // allow bootstrap (no cert) AND mTLS
		MinVersion:   tls.VersionTLS13,
	}

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))

	base := New(lis.Addr().String(), &memStore{}, nil)
	_ = base.ConfigureMTLS(config.TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   caPath,
		Enabled:  true,
	})

	enrollSrv := &enrollingServer{Server: base, pki: pki}
	kitev1.RegisterCollectorServiceServer(srv, enrollSrv)

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), func() { srv.GracefulStop() }
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

// dialWithMTLS creates a gRPC client connection using mTLS credentials.
func dialWithMTLS(t *testing.T, addr string, caCertPEM, clientCertPEM, clientKeyPEM []byte) *grpc.ClientConn {
	t.Helper()

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertPEM))

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	return conn
}

// dialBootstrapTLS creates a gRPC client with server-auth only (no client cert)
// for the enrollment handshake.
func dialBootstrapTLS(t *testing.T, addr string, caCertPEM []byte) *grpc.ClientConn {
	t.Helper()

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertPEM))

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	return conn
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestEnrollment_FullRoundTrip exercises the complete enrollment → mTLS
// connection flow:
//  1. Agent connects with bootstrap TLS (no client cert) and calls Enroll
//  2. Server validates the enrollment token and issues a CA-signed client cert
//  3. Agent stores the returned credentials
//  4. Agent reconnects using the issued mTLS credentials
//  5. Agent calls Heartbeat to verify the mTLS channel works
func TestEnrollment_FullRoundTrip(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// --- Step 1: Bootstrap connection (no client cert) ---
	bootstrapConn := dialBootstrapTLS(t, addr, pki.caCertPEM)
	defer func() { _ = bootstrapConn.Close() }()

	client := kitev1.NewCollectorServiceClient(bootstrapConn)

	// --- Step 2: Enroll with valid token ---
	agentID := uuid.Must(uuid.NewV7()).String()
	enrollResp, err := client.Enroll(ctx, &kitev1.EnrollRequest{
		AgentId:            agentID,
		PublicKey:          "test-pubkey-b64",
		Hostname:           "test-host",
		MachineFingerprint: "test-fp",
		EnrollmentToken:    "valid-token",
		AgentVersion:       "test",
		OsFamily:           "linux",
	})
	require.NoError(t, err)
	assert.Equal(t, "enrolled", enrollResp.Status)
	assert.NotEmpty(t, enrollResp.CaCertificate)
	assert.NotEmpty(t, enrollResp.ClientCertificate)
	assert.NotEmpty(t, enrollResp.ClientKeyEncrypted)
	assert.Greater(t, enrollResp.CertificateExpiresAt, time.Now().Unix())

	t.Log("enrollment succeeded, agent received mTLS credentials")

	// --- Step 3: Store credentials ---
	credDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(credDir, "ca.pem"), enrollResp.CaCertificate, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(credDir, "agent.pem"), enrollResp.ClientCertificate, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(credDir, "agent-key.pem"), enrollResp.ClientKeyEncrypted, 0o600))

	// Verify key file permissions.
	info, err := os.Stat(filepath.Join(credDir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// --- Step 4: Reconnect with enrolled mTLS credentials ---
	mtlsConn := dialWithMTLS(t, addr,
		enrollResp.CaCertificate,
		enrollResp.ClientCertificate,
		enrollResp.ClientKeyEncrypted,
	)
	defer func() { _ = mtlsConn.Close() }()

	mtlsClient := kitev1.NewCollectorServiceClient(mtlsConn)

	// --- Step 5: Heartbeat over mTLS channel ---
	hbResp, err := mtlsClient.Heartbeat(ctx, &kitev1.HeartbeatRequest{
		AgentId: agentID,
	})
	require.NoError(t, err)
	assert.NotNil(t, hbResp.ServerTime)
	// Server time should be within 5 seconds of now.
	serverTime := hbResp.ServerTime.AsTime()
	assert.WithinDuration(t, time.Now(), serverTime, 5*time.Second)

	t.Log("heartbeat over mTLS succeeded")
}

// TestEnrollment_InvalidToken verifies that enrollment is rejected when the
// agent provides an invalid token.
func TestEnrollment_InvalidToken(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := dialBootstrapTLS(t, addr, pki.caCertPEM)
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	_, err := client.Enroll(ctx, &kitev1.EnrollRequest{
		AgentId:         uuid.Must(uuid.NewV7()).String(),
		EnrollmentToken: "wrong-token",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	t.Log("invalid token correctly rejected")
}

// TestEnrollment_MissingToken verifies that enrollment requires a token.
func TestEnrollment_MissingToken(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := dialBootstrapTLS(t, addr, pki.caCertPEM)
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	_, err := client.Enroll(ctx, &kitev1.EnrollRequest{
		AgentId: uuid.Must(uuid.NewV7()).String(),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// TestMTLS_PreIssuedCert verifies that a pre-issued client certificate
// (like those generated by `make certs`) works for mTLS connections.
func TestMTLS_PreIssuedCert(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Issue a client cert directly (simulating `make certs`).
	clientCert, clientKey := pki.issueClientCert(t, "pre-issued-agent")

	conn := dialWithMTLS(t, addr, pki.caCertPEM, clientCert, clientKey)
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	resp, err := client.Heartbeat(ctx, &kitev1.HeartbeatRequest{
		AgentId: "pre-issued-agent",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp.ServerTime)

	t.Log("pre-issued mTLS cert accepted")
}

// TestMTLS_UntrustedCertRejected verifies that a client certificate signed
// by a different CA is rejected by the server.
func TestMTLS_UntrustedCertRejected(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a second, untrusted CA and issue a client cert from it.
	rogueCA := newTestPKI(t)
	rogueCert, rogueKey := rogueCA.issueClientCert(t, "rogue-agent")

	// The client trusts the real CA (so TLS handshake starts), but presents
	// a cert signed by the rogue CA — the server must reject it.
	conn := dialWithMTLS(t, addr, pki.caCertPEM, rogueCert, rogueKey)
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	_, err := client.Heartbeat(ctx, &kitev1.HeartbeatRequest{
		AgentId: "rogue-agent",
	})
	require.Error(t, err, "server should reject cert signed by untrusted CA")

	t.Log("untrusted cert correctly rejected")
}

// TestMTLS_CertStorageRoundTrip verifies that credentials can be stored to
// disk and reloaded to establish a new mTLS connection.
func TestMTLS_CertStorageRoundTrip(t *testing.T) {
	pki := newTestPKI(t)
	addr, cleanup := startTestServer(t, pki)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Enroll to get credentials.
	conn := dialBootstrapTLS(t, addr, pki.caCertPEM)
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	agentID := uuid.Must(uuid.NewV7()).String()
	resp, err := client.Enroll(ctx, &kitev1.EnrollRequest{
		AgentId:         agentID,
		EnrollmentToken: "valid-token",
		Hostname:        "storage-test-host",
		OsFamily:        "linux",
	})
	require.NoError(t, err)

	// Store credentials to disk.
	credDir := t.TempDir()
	caPath := writePEM(t, credDir, "ca.pem", resp.CaCertificate)
	certPath := writePEM(t, credDir, "agent.pem", resp.ClientCertificate)
	keyPath := writePEM(t, credDir, "agent-key.pem", resp.ClientKeyEncrypted)

	// Reload credentials from disk (simulating a restart).
	storedCA, err := os.ReadFile(caPath)
	require.NoError(t, err)
	storedCert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	storedKey, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	// Connect with reloaded credentials.
	conn2 := dialWithMTLS(t, addr, storedCA, storedCert, storedKey)
	defer func() { _ = conn2.Close() }()

	// Use the same agent_id — Heartbeat now validates it matches the cert CN (RFC-0063).
	client2 := kitev1.NewCollectorServiceClient(conn2)
	hbResp, err := client2.Heartbeat(ctx, &kitev1.HeartbeatRequest{AgentId: agentID})
	require.NoError(t, err)
	assert.NotNil(t, hbResp.ServerTime)

	t.Log("credentials survived disk round-trip")
}
