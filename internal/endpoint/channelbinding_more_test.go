package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// fakeAuthInfo is a non-TLS credentials.AuthInfo.
type fakeAuthInfo struct{}

func (fakeAuthInfo) AuthType() string { return "fake" }

// fakeTransportCreds is a scriptable inner TransportCredentials.
type fakeTransportCreds struct {
	handshakeErr error
	overrideErr  error
	authInfo     credentials.AuthInfo
	info         credentials.ProtocolInfo
	overridden   string
}

func (f *fakeTransportCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if f.handshakeErr != nil {
		return nil, nil, f.handshakeErr
	}
	return conn, f.authInfo, nil
}

func (f *fakeTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if f.handshakeErr != nil {
		return nil, nil, f.handshakeErr
	}
	return conn, f.authInfo, nil
}

func (f *fakeTransportCreds) Info() credentials.ProtocolInfo { return f.info }

func (f *fakeTransportCreds) Clone() credentials.TransportCredentials {
	clone := *f
	return &clone
}

func (f *fakeTransportCreds) OverrideServerName(name string) error {
	f.overridden = name
	return f.overrideErr
}

// testTLSServerCert generates an in-memory self-signed server keypair.
func testTLSServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kite-cb-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// realTLSStates performs an in-memory TLS 1.3 handshake over net.Pipe and
// returns both sides' connection states, whose keying-material exporters
// are functional (unlike a zero tls.ConnectionState).
func realTLSStates(t *testing.T) (client, server tls.ConnectionState) {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	srv := tls.Server(srvConn, &tls.Config{
		Certificates: []tls.Certificate{testTLSServerCert(t)},
		MinVersion:   tls.VersionTLS13,
	})
	cli := tls.Client(cliConn, &tls.Config{
		InsecureSkipVerify: true, //#nosec G402 -- in-memory pipe handshake against a throwaway cert
		MinVersion:         tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.HandshakeContext(ctx) }()
	require.NoError(t, cli.HandshakeContext(ctx))
	require.NoError(t, <-errCh)
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli.ConnectionState(), srv.ConnectionState()
}

func exporterBinding(t *testing.T, state tls.ConnectionState) string {
	t.Helper()
	raw, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestTLSStateCapture_ClientHandshakeCachesTLSState(t *testing.T) {
	t.Parallel()

	cliState, _ := realTLSStates(t)
	inner := &fakeTransportCreds{authInfo: credentials.TLSInfo{State: cliState}}
	capture := NewTLSStateCapture(inner)

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	conn, auth, err := capture.ClientHandshake(context.Background(), "backend.example:443", c1)
	require.NoError(t, err)
	assert.Same(t, c1, conn, "the wrapped conn must pass through unchanged")
	require.IsType(t, credentials.TLSInfo{}, auth)

	got, ok := capture.GetState("backend.example:443")
	require.True(t, ok, "a successful TLS handshake must be cached under its authority")
	assert.Equal(t, cliState.Version, got.Version)

	_, ok = capture.GetState("other.example:443")
	assert.False(t, ok)
}

func TestTLSStateCapture_ClientHandshakeNonTLSNotCached(t *testing.T) {
	t.Parallel()

	capture := NewTLSStateCapture(&fakeTransportCreds{authInfo: fakeAuthInfo{}})
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	_, _, err := capture.ClientHandshake(context.Background(), "plain.example:80", c1)
	require.NoError(t, err)
	_, ok := capture.GetState("plain.example:80")
	assert.False(t, ok, "non-TLS auth info must not populate the state cache")
}

func TestTLSStateCapture_ClientHandshakeErrorWrapped(t *testing.T) {
	t.Parallel()

	cause := errors.New("handshake refused")
	capture := NewTLSStateCapture(&fakeTransportCreds{handshakeErr: cause})
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	_, _, err := capture.ClientHandshake(context.Background(), "backend.example:443", c1)
	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "client handshake: ")
	_, ok := capture.GetState("backend.example:443")
	assert.False(t, ok)
}

func TestTLSStateCapture_ServerHandshake(t *testing.T) {
	t.Parallel()

	capture := NewTLSStateCapture(&fakeTransportCreds{authInfo: fakeAuthInfo{}})
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	conn, auth, err := capture.ServerHandshake(c1)
	require.NoError(t, err)
	assert.Same(t, c1, conn)
	assert.Equal(t, "fake", auth.AuthType())

	failing := NewTLSStateCapture(&fakeTransportCreds{handshakeErr: errors.New("bad hello")})
	_, _, err = failing.ServerHandshake(c1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server handshake: ")
	assert.Contains(t, err.Error(), "bad hello")
}

func TestTLSStateCapture_InfoDelegates(t *testing.T) {
	t.Parallel()

	inner := &fakeTransportCreds{info: credentials.ProtocolInfo{
		SecurityProtocol: "tls",
	}}
	capture := NewTLSStateCapture(inner)
	info := capture.Info()
	assert.Equal(t, "tls", info.SecurityProtocol,
		"Info must delegate to the inner credentials verbatim")
}

func TestTLSStateCapture_CloneStartsWithEmptyCache(t *testing.T) {
	t.Parallel()

	capture := NewTLSStateCapture(&fakeTransportCreds{})
	capture.mu.Lock()
	capture.states["seed.example:443"] = tls.ConnectionState{Version: tls.VersionTLS13}
	capture.mu.Unlock()

	cloned := capture.Clone()
	clonedCapture, ok := cloned.(*TLSStateCapture)
	require.True(t, ok, "Clone must return another TLSStateCapture")
	require.NotSame(t, capture, clonedCapture)
	_, ok = clonedCapture.GetState("seed.example:443")
	assert.False(t, ok, "the clone's state cache must start empty")
}

func TestTLSStateCapture_OverrideServerName(t *testing.T) {
	t.Parallel()

	inner := &fakeTransportCreds{}
	capture := NewTLSStateCapture(inner)
	require.NoError(t, capture.OverrideServerName("override.example"))
	assert.Equal(t, "override.example", inner.overridden, "the override must reach the inner credentials")

	failing := &fakeTransportCreds{overrideErr: errors.New("nope")}
	err := NewTLSStateCapture(failing).OverrideServerName("x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "override server name: ")
}

// newTestClientConn returns a lazy (never-dialed) ClientConn whose Target()
// is stable, for exercising the interceptors without any network.
func newTestClientConn(t *testing.T, target string) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func TestChannelBindingInterceptor_AttachesBinding(t *testing.T) {
	t.Parallel()

	cliState, _ := realTLSStates(t)
	cc := newTestClientConn(t, "passthrough:///cb-unary")

	capture := NewTLSStateCapture(&fakeTransportCreds{})
	capture.mu.Lock()
	capture.states[cc.Target()] = cliState
	capture.mu.Unlock()

	want := exporterBinding(t, cliState)

	var gotBinding []string
	invoker := func(ctx context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		require.True(t, ok, "outgoing metadata must be present")
		gotBinding = md.Get(channelBindingHeader)
		return nil
	}

	err := ChannelBindingInterceptor(capture)(context.Background(), "/kite.v1/Heartbeat", nil, nil, cc, invoker)
	require.NoError(t, err)
	require.Len(t, gotBinding, 1)
	assert.Equal(t, want, gotBinding[0], "the header must carry the RFC 9266 exporter value")
}

func TestChannelBindingInterceptor_NoCachedStateSendsNothing(t *testing.T) {
	t.Parallel()

	cc := newTestClientConn(t, "passthrough:///cb-nostate")
	capture := NewTLSStateCapture(&fakeTransportCreds{})

	invoked := false
	invoker := func(ctx context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		invoked = true
		md, ok := metadata.FromOutgoingContext(ctx)
		if ok {
			assert.Empty(t, md.Get(channelBindingHeader))
		}
		return nil
	}

	err := ChannelBindingInterceptor(capture)(context.Background(), "/m", nil, nil, cc, invoker)
	require.NoError(t, err)
	assert.True(t, invoked)
}

func TestChannelBindingStreamInterceptor_AttachesBinding(t *testing.T) {
	t.Parallel()

	cliState, _ := realTLSStates(t)
	cc := newTestClientConn(t, "passthrough:///cb-stream")

	capture := NewTLSStateCapture(&fakeTransportCreds{})
	capture.mu.Lock()
	capture.states[cc.Target()] = cliState
	capture.mu.Unlock()

	want := exporterBinding(t, cliState)

	var gotBinding []string
	streamer := func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		md, ok := metadata.FromOutgoingContext(ctx)
		require.True(t, ok)
		gotBinding = md.Get(channelBindingHeader)
		return nil, nil
	}

	_, err := ChannelBindingStreamInterceptor(capture)(context.Background(), &grpc.StreamDesc{}, cc, "/m", streamer)
	require.NoError(t, err)
	require.Len(t, gotBinding, 1)
	assert.Equal(t, want, gotBinding[0])
}

func TestChannelBindingStreamInterceptor_NilCapturePassesThrough(t *testing.T) {
	t.Parallel()

	called := false
	streamer := func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		called = true
		_, ok := metadata.FromOutgoingContext(ctx)
		assert.False(t, ok, "nil capture must not attach metadata")
		return nil, nil
	}
	_, err := ChannelBindingStreamInterceptor(nil)(context.Background(), &grpc.StreamDesc{}, nil, "/m", streamer)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestVerifyChannelBinding_SkipCases(t *testing.T) {
	t.Parallel()

	// No metadata at all.
	require.NoError(t, VerifyChannelBinding(context.Background()))

	// Metadata without a binding header.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "v"))
	require.NoError(t, VerifyChannelBinding(ctx))

	// Binding sent but no request info in the context.
	ctx = metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(channelBindingHeader, "Zm9v"))
	require.NoError(t, VerifyChannelBinding(ctx))

	// Request info present but with no auth info.
	ctx = credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{})
	require.NoError(t, VerifyChannelBinding(ctx))

	// Auth info present but not TLS.
	ctx = metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(channelBindingHeader, "Zm9v"))
	ctx = credentials.NewContextWithRequestInfo(ctx,
		credentials.RequestInfo{AuthInfo: fakeAuthInfo{}})
	require.NoError(t, VerifyChannelBinding(ctx))
}

func TestVerifyChannelBinding_MatchingBinding(t *testing.T) {
	t.Parallel()

	cliState, srvState := realTLSStates(t)

	// The client sends its exporter value; the server compares against its
	// own side of the same session — they must agree.
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(channelBindingHeader, exporterBinding(t, cliState)))
	ctx = credentials.NewContextWithRequestInfo(ctx,
		credentials.RequestInfo{AuthInfo: credentials.TLSInfo{State: srvState}})

	require.NoError(t, VerifyChannelBinding(ctx))
}

func TestVerifyChannelBinding_MismatchDetected(t *testing.T) {
	t.Parallel()

	// Bindings from two DIFFERENT TLS sessions — the proxied-connection case.
	otherCliState, _ := realTLSStates(t)
	_, srvState := realTLSStates(t)

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(channelBindingHeader, exporterBinding(t, otherCliState)))
	ctx = credentials.NewContextWithRequestInfo(ctx,
		credentials.RequestInfo{AuthInfo: credentials.TLSInfo{State: srvState}})

	err := VerifyChannelBinding(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel binding mismatch")
}
