package grpcapi

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
)

// serveOnEphemeralPort starts srv on a loopback ephemeral port and returns the
// address it actually bound.
//
// Serve owns the bind, so the port is never released between being chosen and
// being served: picking a port with a probe listener and closing it first
// leaves a window where a dial races the rebind (connection refused) or another
// process claims the port outright.
func serveOnEphemeralPort(t *testing.T, srv *Server) string {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after Stop")
		}
	})

	// Serve publishes the bound address before it starts accepting; once it is
	// set the socket is listening, so a dial lands in the accept queue rather
	// than being refused.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if addr := srv.Addr(); addr != "" {
			return addr
		}
		select {
		case err := <-done:
			require.FailNowf(t, "Serve returned before binding", "err: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			require.FailNow(t, "Serve did not bind a port within 10s")
		}
		time.Sleep(time.Millisecond)
	}
}

// dialInsecure returns a client speaking plaintext to addr.
func dialInsecure(t *testing.T, addr string) kitev1.CollectorServiceClient {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return kitev1.NewCollectorServiceClient(conn)
}

// startInsecureServer boots the plaintext loopback listener path (the
// "not recommended for production" warning branch) and returns a
// connected client.
func startInsecureServer(t *testing.T) kitev1.CollectorServiceClient {
	t.Helper()

	srv := New("127.0.0.1:0", nil, nil)
	srv.SetPanicsRecovered(prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "test_grpc_panics_total"}, []string{"component"}))

	return dialInsecure(t, serveOnEphemeralPort(t, srv))
}

func TestServeInsecure_HeartbeatRoundTrip(t *testing.T) {
	client := startInsecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Heartbeat(ctx, &kitev1.HeartbeatRequest{AgentId: "agent-1"})
	require.NoError(t, err, "without mTLS there is no CN to mismatch")
	require.NotNil(t, resp.GetServerTime())
	assert.WithinDuration(t, time.Now(), resp.GetServerTime().AsTime(), time.Minute)
}

func TestServeInsecure_PlaceholderRPCsAreUnimplemented(t *testing.T) {
	client := startInsecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.Enroll(ctx, &kitev1.EnrollRequest{AgentId: "a", Hostname: "h"})
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err),
		"enrollment is the fleet manager's job")

	_, err = client.RenewCertificate(ctx, &kitev1.RenewRequest{AgentId: "a"})
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ReportFindings accepts and acknowledges a client stream with an exact
// accepted count.
func TestServeInsecure_ReportFindingsStream(t *testing.T) {
	client := startInsecureServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.ReportFindings(ctx)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, stream.Send(&kitev1.ConfigFinding{RuleId: "ssh-001"}))
	}
	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	assert.EqualValues(t, 3, resp.GetAccepted())
	assert.EqualValues(t, 0, resp.GetRejected())
}

// Private privacy mode disables machine ingestion outright: the stream
// errors with PermissionDenied before any snapshot is consumed.
func TestServeInsecure_PrivateModeRefusesMachines(t *testing.T) {
	srv := New("127.0.0.1:0", nil, nil)
	srv.SetPrivacyMode(PrivacyModePrivate)
	client := dialInsecure(t, serveOnEphemeralPort(t, srv))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.ReportMachines(ctx)
	require.NoError(t, err)
	// The denial surfaces on send/close, depending on stream buffering.
	if sendErr := stream.Send(&kitev1.MachineSnapshot{Hostname: "h"}); sendErr != nil {
		require.True(t, errors.Is(sendErr, io.EOF) || status.Code(sendErr) == codes.PermissionDenied)
	}
	_, err = stream.CloseAndRecv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A Stop that beats Serve to the bind must not strand Serve: before the server
// was published under the mutex, Stop saw a nil *grpc.Server, returned without
// stopping anything, and Serve blocked on the listener forever.
func TestStop_BeforeServeDoesNotStrandServe(t *testing.T) {
	srv := New("127.0.0.1:0", nil, nil)
	srv.Stop()

	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()

	select {
	case err := <-done:
		require.NoError(t, err, "Serve should stand down cleanly, not error")
	case <-time.After(10 * time.Second):
		t.Fatal("Serve blocked after a Stop that preceded it")
	}

	assert.Empty(t, srv.Addr(), "a server that stood down never publishes an address")
}

// Addr resolves the concrete port when the server is configured with :0.
func TestAddr_ResolvesEphemeralPort(t *testing.T) {
	srv := New("127.0.0.1:0", nil, nil)
	addr := serveOnEphemeralPort(t, srv)

	assert.Equal(t, addr, srv.Addr())
	assert.NotEqual(t, "127.0.0.1:0", addr, "the ephemeral port must be resolved")

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEqual(t, "0", port)
}

func TestServe_ListenFailure(t *testing.T) {
	// Hold the port so Serve cannot bind it.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	srv := New(ln.Addr().String(), nil, nil)
	err = srv.Serve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen")
	srv.Stop() // Stop with no grpc server must be a safe no-op
}
