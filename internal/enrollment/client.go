// Package enrollment implements the agent-side enrollment handshake.
// It connects to a backend endpoint using bootstrap TLS (server-only auth)
// and performs the Enroll RPC to obtain mTLS credentials.
package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/identity"
)

// Result holds the outcome of a successful enrollment.
type Result struct {
	Status             string
	JWKSURL            string
	CACertificate      []byte
	ClientCertificate  []byte
	ClientKey          []byte
	CertificateExpires int64
}

// Client performs enrollment handshakes with backend endpoints.
type Client struct {
	logger *slog.Logger
}

// NewClient creates a new enrollment client.
func NewClient(logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{logger: logger}
}

// Enroll connects to the given address using bootstrap TLS and performs
// the enrollment handshake. If caFile is non-empty, it is used as the
// server CA; otherwise the system CA pool is used.
func (c *Client) Enroll(ctx context.Context, address, token, caFile string, id *identity.Identity) (*Result, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load custom CA if provided for bootstrap trust.
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 — path from trusted CLI flag
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q contains no valid certificates", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}
	defer func() { _ = conn.Close() }()

	client := kitev1.NewCollectorServiceClient(conn)

	hostname, _ := os.Hostname()
	req := &kitev1.EnrollRequest{
		AgentId:            id.AgentID.String(),
		PublicKey:          id.PubKeyB64,
		Hostname:           hostname,
		MachineFingerprint: identity.MachineFingerprint(),
		EnrollmentToken:    token,
		AgentVersion:       "dev",
		OsFamily:           runtime.GOOS,
	}

	c.logger.Info("enrolling with endpoint", "address", address)

	resp, err := client.Enroll(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("enroll RPC: %w", err)
	}

	return &Result{
		Status:             resp.Status,
		CACertificate:      resp.CaCertificate,
		ClientCertificate:  resp.ClientCertificate,
		ClientKey:          resp.ClientKeyEncrypted,
		CertificateExpires: resp.CertificateExpiresAt,
		JWKSURL:            resp.JwksUrl,
	}, nil
}

// StoreCertificates persists the enrollment result to the endpoint's
// credential directory under dataDir/<endpointName>/.
func StoreCertificates(dataDir, endpointName string, result *Result) error {
	dir := filepath.Join(dataDir, endpointName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}

	files := map[string]struct {
		data []byte
		perm os.FileMode
	}{
		"ca.pem":        {data: result.CACertificate, perm: 0644},
		"agent.pem":     {data: result.ClientCertificate, perm: 0644},
		"agent-key.pem": {data: result.ClientKey, perm: 0600},
	}

	for name, f := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, f.data, f.perm); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return nil
}

