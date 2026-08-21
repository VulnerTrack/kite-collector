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

// startInsecureServer boots the plaintext loopback listener path (the
// "not recommended for production" warning branch) and returns a
// connected client.
func startInsecureServer(t *testing.T) kitev1.CollectorServiceClient {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close(), "release the probe port for Serve to rebind")

	srv := New(addr, nil, nil)
	srv.SetPanicsRecovered(prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "test_grpc_panics_total"}, []string{"component"}))

	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Stop")
		}
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return kitev1.NewCollectorServiceClient(conn)
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
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	srv := New(addr, nil, nil)
	srv.SetPrivacyMode(PrivacyModePrivate)
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		<-done
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := kitev1.NewCollectorServiceClient(conn)

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
