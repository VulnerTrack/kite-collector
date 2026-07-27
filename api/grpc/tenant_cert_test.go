package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// These tests verify the authoritative tenancy boundary on the ingest path:
// the server derives tenant_id from the mTLS client certificate Organization
// and stamps it onto every persisted machine, regardless of what the agent
// sends. The wire type (MachineSnapshot) has no tenant field at all, so a
// tenant can only ever come from the certificate — the property under test.

// Tenant identifiers are well-formed UUIDs: peerTenantID accepts a certificate
// Organization only when it parses as one.
const (
	tenantAlpha = "11111111-1111-4111-8111-111111111111"
	tenantBeta  = "22222222-2222-4222-8222-222222222222"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// capturingStore embeds memStore (which satisfies the full store.Store
// surface) and records every machine handed to UpsertMachine so a test can
// assert the tenant the server stamped on it.
type capturingStore struct {
	*memStore
	mu       sync.Mutex
	machines []model.Machine
}

func (c *capturingStore) UpsertMachine(_ context.Context, m model.Machine) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.machines = append(c.machines, m)
	return nil
}

func (c *capturingStore) captured() []model.Machine {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]model.Machine, len(c.machines))
	copy(out, c.machines)
	return out
}

// fakeReportStream is a client-streaming ReportMachines server stream that
// replays a fixed queue of snapshots then io.EOF, and records the final
// ReportResponse. Only Context/Recv/SendAndClose are exercised by the server.
type fakeReportStream struct {
	grpc.ServerStream
	ctx   context.Context
	snaps []*kitev1.MachineSnapshot
	idx   int
	resp  *kitev1.ReportResponse
}

func (f *fakeReportStream) Context() context.Context { return f.ctx }

func (f *fakeReportStream) Recv() (*kitev1.MachineSnapshot, error) {
	if f.idx >= len(f.snaps) {
		return nil, io.EOF
	}
	s := f.snaps[f.idx]
	f.idx++
	return s, nil
}

func (f *fakeReportStream) SendAndClose(r *kitev1.ReportResponse) error {
	f.resp = r
	return nil
}

// certPeerContext returns a context carrying a gRPC peer whose mTLS leaf
// certificate has the given CN and Organizations — the exact fields
// peerTenantID/peerCN read. The certificate is a bare x509 struct: the server
// only reads Subject fields here; chain verification is the TLS layer's job
// and is exercised separately by mtls_integration_test.go.
func certPeerContext(cn string, orgs ...string) context.Context {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn, Organization: orgs}}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
}

func newTenancyServer(t *testing.T) (*Server, *capturingStore) {
	t.Helper()
	cs := &capturingStore{memStore: &memStore{}}
	return New(":0", cs, nil), cs
}

func snap(hostname string) *kitev1.MachineSnapshot {
	return &kitev1.MachineSnapshot{Hostname: hostname, MachineType: "server"}
}

// ---------------------------------------------------------------------------
// Tenant derivation from the certificate
// ---------------------------------------------------------------------------

func TestReportMachines_StampsTenantFromCertOrganization(t *testing.T) {
	srv, cs := newTenancyServer(t)
	stream := &fakeReportStream{
		ctx:   certPeerContext("agent-1", tenantAlpha),
		snaps: []*kitev1.MachineSnapshot{snap("web-01")},
	}

	require.NoError(t, srv.ReportMachines(stream))

	got := cs.captured()
	require.Len(t, got, 1)
	assert.Equal(t, tenantAlpha, got[0].TenantID,
		"tenant must be taken from the mTLS cert Organization, never from client data")
	require.NotNil(t, stream.resp)
	assert.Equal(t, int32(1), stream.resp.Accepted)
}

func TestReportMachines_TenantIsolation_DifferentCertsDifferentScopes(t *testing.T) {
	srv, cs := newTenancyServer(t)

	// The SAME hostname reported under two different tenant certificates.
	for _, tc := range []struct{ agent, tenant string }{
		{"agent-a", tenantAlpha},
		{"agent-b", tenantBeta},
	} {
		stream := &fakeReportStream{
			ctx:   certPeerContext(tc.agent, tc.tenant),
			snaps: []*kitev1.MachineSnapshot{snap("shared-host")},
		}
		require.NoError(t, srv.ReportMachines(stream))
	}

	got := cs.captured()
	require.Len(t, got, 2)
	assert.Equal(t, tenantAlpha, got[0].TenantID)
	assert.Equal(t, tenantBeta, got[1].TenantID)
	// Tenant-scoped dedup: an identical hostname in two tenants must not share
	// a natural key, or the tenants would collide in the store.
	assert.NotEqual(t, got[0].NaturalKey, got[1].NaturalKey,
		"identical hostnames in different tenants must produce different natural keys")
	assert.NotEmpty(t, got[0].NaturalKey)
}

func TestReportMachines_NoPeerCert_TenantEmpty(t *testing.T) {
	srv, cs := newTenancyServer(t)
	stream := &fakeReportStream{
		ctx:   context.Background(), // no gRPC peer -> no mTLS
		snaps: []*kitev1.MachineSnapshot{snap("h")},
	}

	require.NoError(t, srv.ReportMachines(stream))

	got := cs.captured()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].TenantID, "no certificate -> no tenant scope")
}

func TestReportMachines_CertWithoutOrganization_TenantEmpty(t *testing.T) {
	srv, cs := newTenancyServer(t)
	stream := &fakeReportStream{
		ctx:   certPeerContext("agent-no-org"), // CN present, no Organization
		snaps: []*kitev1.MachineSnapshot{snap("h")},
	}

	require.NoError(t, srv.ReportMachines(stream))

	got := cs.captured()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].TenantID)
}

func TestReportMachines_MalformedTenantOrganization_TenantEmpty(t *testing.T) {
	srv, cs := newTenancyServer(t)
	stream := &fakeReportStream{
		ctx:   certPeerContext("agent", "acme-corp"), // Organization present but not a UUID
		snaps: []*kitev1.MachineSnapshot{snap("h")},
	}

	require.NoError(t, srv.ReportMachines(stream))

	got := cs.captured()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].TenantID,
		"a non-UUID Organization must not be trusted as a tenant scope")
}

// ---------------------------------------------------------------------------
// peerTenantID unit behaviour
// ---------------------------------------------------------------------------

func TestPeerTenantID(t *testing.T) {
	t.Run("from cert Organization", func(t *testing.T) {
		assert.Equal(t, tenantAlpha, peerTenantID(certPeerContext("cn", tenantAlpha)))
	})
	t.Run("first of multiple Organizations", func(t *testing.T) {
		assert.Equal(t, tenantAlpha,
			peerTenantID(certPeerContext("cn", tenantAlpha, tenantBeta)))
	})
	t.Run("normalizes case to a stable namespace", func(t *testing.T) {
		assert.Equal(t, "abcdef00-1111-4111-8111-111111111111",
			peerTenantID(certPeerContext("cn", "ABCDEF00-1111-4111-8111-111111111111")),
			"upper- and lower-case UUIDs must map to the same tenant namespace")
	})
	t.Run("rejects non-UUID Organization", func(t *testing.T) {
		assert.Equal(t, "", peerTenantID(certPeerContext("cn", "acme-corp")),
			"a non-UUID Organization must not become a tenant scope")
	})
	t.Run("no peer in context", func(t *testing.T) {
		assert.Equal(t, "", peerTenantID(context.Background()))
	})
	t.Run("cert without Organization", func(t *testing.T) {
		assert.Equal(t, "", peerTenantID(certPeerContext("cn")))
	})
}

// ---------------------------------------------------------------------------
// Tenant enforcement: a presented client certificate MUST carry a valid tenant
// Organization, or the call is rejected with PermissionDenied (gRPC → 403).
// ---------------------------------------------------------------------------

func TestReportMachines_RejectsCertWithNoTenantOrganization(t *testing.T) {
	srv, cs := newTenancyServer(t)
	srv.SetTenantEnforcement(true)
	stream := &fakeReportStream{
		ctx:   certPeerContext("agent-1"), // cert presented, NO Organization
		snaps: []*kitev1.MachineSnapshot{snap("web-01")},
	}

	err := srv.ReportMachines(stream)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"a cert without a valid tenant Organization must be denied, not accepted untenanted")
	assert.Empty(t, cs.captured(), "no machine may be stored under a rejected tenant")
}

func TestReportMachines_RejectsCertWithMalformedTenantOrganization(t *testing.T) {
	srv, cs := newTenancyServer(t)
	srv.SetTenantEnforcement(true)
	stream := &fakeReportStream{
		ctx:   certPeerContext("agent-1", "not-a-uuid"),
		snaps: []*kitev1.MachineSnapshot{snap("web-01")},
	}

	err := srv.ReportMachines(stream)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, cs.captured())
}

func TestReportMachines_AllowsPlaintextPeerUntenanted(t *testing.T) {
	// No mTLS (dev / in-process): untenanted is still allowed, unchanged.
	srv, cs := newTenancyServer(t)
	stream := &fakeReportStream{
		ctx:   context.Background(), // no peer / no cert
		snaps: []*kitev1.MachineSnapshot{snap("web-01")},
	}

	require.NoError(t, srv.ReportMachines(stream))
	got := cs.captured()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].TenantID)
}
