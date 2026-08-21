package kitev1

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fixedTime is a deterministic timestamp used across roundtrip tests.
var fixedTime = time.Date(2026, 8, 21, 10, 30, 45, 123456789, time.UTC)

// roundtrip marshals msg and unmarshals it into out, failing the test on any
// wire error. It returns out for fluent use at call sites.
func roundtrip(t *testing.T, msg, out proto.Message) proto.Message {
	t.Helper()
	raw, err := proto.Marshal(msg)
	require.NoError(t, err)
	require.NoError(t, proto.Unmarshal(raw, out))
	require.True(t, proto.Equal(msg, out), "roundtrip must preserve message equality")
	return out
}

// ---------------------------------------------------------------------------
// Marshal/Unmarshal roundtrips: every field populated, exact getter values.
// ---------------------------------------------------------------------------

func TestMachineSnapshot_Roundtrip(t *testing.T) {
	in := &MachineSnapshot{
		Hostname:    "web-01.corp.example",
		MachineType: "server",
		OsFamily:    "linux",
		OsVersion:   "6.9.1-arch1",
		Environment: "production",
		Owner:       "platform-team",
		Criticality: "high",
		TagsJson:    `{"rack":"r12","dc":"mx-1"}`,
		CollectedAt: timestamppb.New(fixedTime),
		Software: []*InstalledPackage{
			{
				Name:           "openssl",
				Version:        "3.3.1",
				Vendor:         "openssl-project",
				Cpe23:          "cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*",
				PackageManager: "pacman",
			},
			{Name: "curl", Version: "8.8.0"},
		},
		DiscoverySource: "osquery",
	}

	got := &MachineSnapshot{}
	roundtrip(t, in, got)

	assert.Equal(t, "web-01.corp.example", got.GetHostname())
	assert.Equal(t, "server", got.GetMachineType())
	assert.Equal(t, "linux", got.GetOsFamily())
	assert.Equal(t, "6.9.1-arch1", got.GetOsVersion())
	assert.Equal(t, "production", got.GetEnvironment())
	assert.Equal(t, "platform-team", got.GetOwner())
	assert.Equal(t, "high", got.GetCriticality())
	assert.Equal(t, `{"rack":"r12","dc":"mx-1"}`, got.GetTagsJson())
	assert.Equal(t, "osquery", got.GetDiscoverySource())

	require.NotNil(t, got.GetCollectedAt())
	assert.Equal(t, fixedTime.Unix(), got.GetCollectedAt().GetSeconds())
	assert.Equal(t, int32(123456789), got.GetCollectedAt().GetNanos())

	require.Len(t, got.GetSoftware(), 2)
	first := got.GetSoftware()[0]
	assert.Equal(t, "openssl", first.GetName())
	assert.Equal(t, "3.3.1", first.GetVersion())
	assert.Equal(t, "openssl-project", first.GetVendor())
	assert.Equal(t, "cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*", first.GetCpe23())
	assert.Equal(t, "pacman", first.GetPackageManager())
	second := got.GetSoftware()[1]
	assert.Equal(t, "curl", second.GetName())
	assert.Equal(t, "8.8.0", second.GetVersion())
	assert.Equal(t, "", second.GetVendor())
}

func TestConfigFinding_Roundtrip(t *testing.T) {
	in := &ConfigFinding{
		FindingId:   "f-0001",
		MachineId:   "m-42",
		Category:    "ssh",
		RuleId:      "CIS-5.2.8",
		Severity:    "critical",
		Title:       "PermitRootLogin enabled",
		Detail:      "sshd_config allows direct root login",
		Remediation: "Set PermitRootLogin no and reload sshd",
		FoundAt:     timestamppb.New(fixedTime),
	}

	got := &ConfigFinding{}
	roundtrip(t, in, got)

	assert.Equal(t, "f-0001", got.GetFindingId())
	assert.Equal(t, "m-42", got.GetMachineId())
	assert.Equal(t, "ssh", got.GetCategory())
	assert.Equal(t, "CIS-5.2.8", got.GetRuleId())
	assert.Equal(t, "critical", got.GetSeverity())
	assert.Equal(t, "PermitRootLogin enabled", got.GetTitle())
	assert.Equal(t, "sshd_config allows direct root login", got.GetDetail())
	assert.Equal(t, "Set PermitRootLogin no and reload sshd", got.GetRemediation())
	require.NotNil(t, got.GetFoundAt())
	assert.Equal(t, fixedTime.Unix(), got.GetFoundAt().GetSeconds())
	assert.Equal(t, int32(123456789), got.GetFoundAt().GetNanos())
}

func TestInstalledPackage_Roundtrip(t *testing.T) {
	in := &InstalledPackage{
		Name:           "nginx",
		Version:        "1.27.0",
		Vendor:         "f5",
		Cpe23:          "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*",
		PackageManager: "apt",
	}

	got := &InstalledPackage{}
	roundtrip(t, in, got)

	assert.Equal(t, "nginx", got.GetName())
	assert.Equal(t, "1.27.0", got.GetVersion())
	assert.Equal(t, "f5", got.GetVendor())
	assert.Equal(t, "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*", got.GetCpe23())
	assert.Equal(t, "apt", got.GetPackageManager())
}

func TestReportResponse_Roundtrip(t *testing.T) {
	in := &ReportResponse{Accepted: 128, Rejected: -3}

	got := &ReportResponse{}
	roundtrip(t, in, got)

	assert.Equal(t, int32(128), got.GetAccepted())
	assert.Equal(t, int32(-3), got.GetRejected())
}

func TestHeartbeatRequest_Roundtrip(t *testing.T) {
	in := &HeartbeatRequest{
		AgentId:       "agent-7",
		AgentVersion:  "1.4.2",
		UptimeSeconds: 86400,
		Status:        "healthy",
	}

	got := &HeartbeatRequest{}
	roundtrip(t, in, got)

	assert.Equal(t, "agent-7", got.GetAgentId())
	assert.Equal(t, "1.4.2", got.GetAgentVersion())
	assert.Equal(t, int64(86400), got.GetUptimeSeconds())
	assert.Equal(t, "healthy", got.GetStatus())
}

func TestHeartbeatResponse_Roundtrip(t *testing.T) {
	in := &HeartbeatResponse{ServerTime: timestamppb.New(fixedTime)}

	got := &HeartbeatResponse{}
	roundtrip(t, in, got)

	require.NotNil(t, got.GetServerTime())
	assert.Equal(t, fixedTime.Unix(), got.GetServerTime().GetSeconds())
	assert.Equal(t, int32(123456789), got.GetServerTime().GetNanos())
}

func TestEnrollRequest_Roundtrip(t *testing.T) {
	in := &EnrollRequest{
		AgentId:            "agent-9",
		PublicKey:          "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
		Hostname:           "db-02",
		MachineFingerprint: "fp:deadbeef",
		EnrollmentToken:    "tok-secret-123",
		AgentVersion:       "2.0.0",
		OsFamily:           "windows",
	}

	got := &EnrollRequest{}
	roundtrip(t, in, got)

	assert.Equal(t, "agent-9", got.GetAgentId())
	assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", got.GetPublicKey())
	assert.Equal(t, "db-02", got.GetHostname())
	assert.Equal(t, "fp:deadbeef", got.GetMachineFingerprint())
	assert.Equal(t, "tok-secret-123", got.GetEnrollmentToken())
	assert.Equal(t, "2.0.0", got.GetAgentVersion())
	assert.Equal(t, "windows", got.GetOsFamily())
}

func TestEnrollResponse_Roundtrip(t *testing.T) {
	in := &EnrollResponse{
		Status:               "enrolled",
		CaCertificate:        []byte("ca-pem"),
		ClientCertificate:    []byte("client-pem"),
		ClientKeyEncrypted:   []byte{0x00, 0x01, 0xFF},
		CertificateExpiresAt: 1790000000,
		JwksUrl:              "https://kite.example/jwks.json",
	}

	got := &EnrollResponse{}
	roundtrip(t, in, got)

	assert.Equal(t, "enrolled", got.GetStatus())
	assert.Equal(t, []byte("ca-pem"), got.GetCaCertificate())
	assert.Equal(t, []byte("client-pem"), got.GetClientCertificate())
	assert.Equal(t, []byte{0x00, 0x01, 0xFF}, got.GetClientKeyEncrypted())
	assert.Equal(t, int64(1790000000), got.GetCertificateExpiresAt())
	assert.Equal(t, "https://kite.example/jwks.json", got.GetJwksUrl())
}

func TestRenewRequest_Roundtrip(t *testing.T) {
	in := &RenewRequest{
		AgentId: "agent-11",
		Csr:     []byte("csr-der-bytes"),
	}

	got := &RenewRequest{}
	roundtrip(t, in, got)

	assert.Equal(t, "agent-11", got.GetAgentId())
	assert.Equal(t, []byte("csr-der-bytes"), got.GetCsr())
}

func TestRenewResponse_Roundtrip(t *testing.T) {
	in := &RenewResponse{
		Status:               "renewed",
		ClientCertificate:    []byte("new-client-pem"),
		CertificateExpiresAt: 1795000000,
	}

	got := &RenewResponse{}
	roundtrip(t, in, got)

	assert.Equal(t, "renewed", got.GetStatus())
	assert.Equal(t, []byte("new-client-pem"), got.GetClientCertificate())
	assert.Equal(t, int64(1795000000), got.GetCertificateExpiresAt())
}

func TestSecureEnvelope_Roundtrip(t *testing.T) {
	in := &SecureEnvelope{
		JweCompact: "eyJhbGciOiJFQ0RILUVTIn0..iv.ciphertext.tag",
		KeyId:      "kid-2026-08",
	}

	got := &SecureEnvelope{}
	roundtrip(t, in, got)

	assert.Equal(t, "eyJhbGciOiJFQ0RILUVTIn0..iv.ciphertext.tag", got.GetJweCompact())
	assert.Equal(t, "kid-2026-08", got.GetKeyId())
}

// ---------------------------------------------------------------------------
// Nil-receiver getters: generated getters are nil-safe and return defaults.
// ---------------------------------------------------------------------------

func TestNilReceiverGetters_ReturnDefaults(t *testing.T) {
	var snap *MachineSnapshot
	assert.Equal(t, "", snap.GetHostname())
	assert.Equal(t, "", snap.GetMachineType())
	assert.Equal(t, "", snap.GetOsFamily())
	assert.Equal(t, "", snap.GetOsVersion())
	assert.Equal(t, "", snap.GetEnvironment())
	assert.Equal(t, "", snap.GetOwner())
	assert.Equal(t, "", snap.GetCriticality())
	assert.Equal(t, "", snap.GetTagsJson())
	assert.Nil(t, snap.GetCollectedAt())
	assert.Nil(t, snap.GetSoftware())
	assert.Equal(t, "", snap.GetDiscoverySource())

	var finding *ConfigFinding
	assert.Equal(t, "", finding.GetFindingId())
	assert.Equal(t, "", finding.GetMachineId())
	assert.Equal(t, "", finding.GetCategory())
	assert.Equal(t, "", finding.GetRuleId())
	assert.Equal(t, "", finding.GetSeverity())
	assert.Equal(t, "", finding.GetTitle())
	assert.Equal(t, "", finding.GetDetail())
	assert.Equal(t, "", finding.GetRemediation())
	assert.Nil(t, finding.GetFoundAt())

	var pkg *InstalledPackage
	assert.Equal(t, "", pkg.GetName())
	assert.Equal(t, "", pkg.GetVersion())
	assert.Equal(t, "", pkg.GetVendor())
	assert.Equal(t, "", pkg.GetCpe23())
	assert.Equal(t, "", pkg.GetPackageManager())

	var report *ReportResponse
	assert.Equal(t, int32(0), report.GetAccepted())
	assert.Equal(t, int32(0), report.GetRejected())

	var hbReq *HeartbeatRequest
	assert.Equal(t, "", hbReq.GetAgentId())
	assert.Equal(t, "", hbReq.GetAgentVersion())
	assert.Equal(t, int64(0), hbReq.GetUptimeSeconds())
	assert.Equal(t, "", hbReq.GetStatus())

	var hbResp *HeartbeatResponse
	assert.Nil(t, hbResp.GetServerTime())

	var enrollReq *EnrollRequest
	assert.Equal(t, "", enrollReq.GetAgentId())
	assert.Equal(t, "", enrollReq.GetPublicKey())
	assert.Equal(t, "", enrollReq.GetHostname())
	assert.Equal(t, "", enrollReq.GetMachineFingerprint())
	assert.Equal(t, "", enrollReq.GetEnrollmentToken())
	assert.Equal(t, "", enrollReq.GetAgentVersion())
	assert.Equal(t, "", enrollReq.GetOsFamily())

	var enrollResp *EnrollResponse
	assert.Equal(t, "", enrollResp.GetStatus())
	assert.Nil(t, enrollResp.GetCaCertificate())
	assert.Nil(t, enrollResp.GetClientCertificate())
	assert.Nil(t, enrollResp.GetClientKeyEncrypted())
	assert.Equal(t, int64(0), enrollResp.GetCertificateExpiresAt())
	assert.Equal(t, "", enrollResp.GetJwksUrl())

	var renewReq *RenewRequest
	assert.Equal(t, "", renewReq.GetAgentId())
	assert.Nil(t, renewReq.GetCsr())

	var renewResp *RenewResponse
	assert.Equal(t, "", renewResp.GetStatus())
	assert.Nil(t, renewResp.GetClientCertificate())
	assert.Equal(t, int64(0), renewResp.GetCertificateExpiresAt())

	var env *SecureEnvelope
	assert.Equal(t, "", env.GetJweCompact())
	assert.Equal(t, "", env.GetKeyId())
}

// ---------------------------------------------------------------------------
// Reset / String / ProtoReflect smoke behavior.
// ---------------------------------------------------------------------------

func TestResetAndString_AllMessages(t *testing.T) {
	messages := []proto.Message{
		&MachineSnapshot{Hostname: "h", Software: []*InstalledPackage{{Name: "p"}}},
		&ConfigFinding{FindingId: "f"},
		&InstalledPackage{Name: "n"},
		&ReportResponse{Accepted: 1},
		&HeartbeatRequest{AgentId: "a"},
		&HeartbeatResponse{ServerTime: timestamppb.New(fixedTime)},
		&EnrollRequest{AgentId: "a"},
		&EnrollResponse{Status: "s"},
		&RenewRequest{AgentId: "a"},
		&RenewResponse{Status: "s"},
		&SecureEnvelope{KeyId: "k"},
	}

	for _, msg := range messages {
		name := string(msg.ProtoReflect().Descriptor().Name())
		assert.NotEmpty(t, msg.ProtoReflect().Descriptor().FullName(),
			"%s must expose a descriptor", name)

		str, ok := msg.(interface{ String() string })
		require.True(t, ok, "%s must implement String", name)
		assert.NotEmpty(t, str.String(), "%s populated String must not be empty", name)

		proto.Reset(msg)
		empty, err := proto.Marshal(msg)
		require.NoError(t, err)
		assert.Empty(t, empty, "%s must marshal to zero bytes after Reset", name)
	}
}

func TestResetClearsFields_ExactValues(t *testing.T) {
	snap := &MachineSnapshot{
		Hostname:    "before-reset",
		CollectedAt: timestamppb.New(fixedTime),
		Software:    []*InstalledPackage{{Name: "x"}},
	}
	snap.Reset()
	assert.Equal(t, "", snap.GetHostname())
	assert.Nil(t, snap.GetCollectedAt())
	assert.Nil(t, snap.GetSoftware())

	resp := &EnrollResponse{Status: "enrolled", CaCertificate: []byte("ca")}
	resp.Reset()
	assert.Equal(t, "", resp.GetStatus())
	assert.Nil(t, resp.GetCaCertificate())
}

func TestProtoReflect_NilReceiverIsInvalid(t *testing.T) {
	assert.False(t, (*MachineSnapshot)(nil).ProtoReflect().IsValid())
	assert.False(t, (*ConfigFinding)(nil).ProtoReflect().IsValid())
	assert.False(t, (*InstalledPackage)(nil).ProtoReflect().IsValid())
	assert.False(t, (*ReportResponse)(nil).ProtoReflect().IsValid())
	assert.False(t, (*HeartbeatRequest)(nil).ProtoReflect().IsValid())
	assert.False(t, (*HeartbeatResponse)(nil).ProtoReflect().IsValid())
	assert.False(t, (*EnrollRequest)(nil).ProtoReflect().IsValid())
	assert.False(t, (*EnrollResponse)(nil).ProtoReflect().IsValid())
	assert.False(t, (*RenewRequest)(nil).ProtoReflect().IsValid())
	assert.False(t, (*RenewResponse)(nil).ProtoReflect().IsValid())
	assert.False(t, (*SecureEnvelope)(nil).ProtoReflect().IsValid())
}

// ---------------------------------------------------------------------------
// UnimplementedCollectorServiceServer: every method returns codes.Unimplemented.
// ---------------------------------------------------------------------------

func TestUnimplementedServer_UnaryMethods(t *testing.T) {
	srv := UnimplementedCollectorServiceServer{}
	ctx := context.Background()

	hbResp, err := srv.Heartbeat(ctx, &HeartbeatRequest{})
	assert.Nil(t, hbResp)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "method Heartbeat not implemented", status.Convert(err).Message())

	enrollResp, err := srv.Enroll(ctx, &EnrollRequest{})
	assert.Nil(t, enrollResp)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "method Enroll not implemented", status.Convert(err).Message())

	renewResp, err := srv.RenewCertificate(ctx, &RenewRequest{})
	assert.Nil(t, renewResp)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "method RenewCertificate not implemented", status.Convert(err).Message())
}

func TestUnimplementedServer_StreamingMethods(t *testing.T) {
	srv := UnimplementedCollectorServiceServer{}

	err := srv.ReportMachines(nil)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "method ReportMachines not implemented", status.Convert(err).Message())

	err = srv.ReportFindings(nil)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "method ReportFindings not implemented", status.Convert(err).Message())

	// Marker methods must be callable no-ops.
	srv.mustEmbedUnimplementedCollectorServiceServer()
	srv.testEmbeddedByValue()
}

// ---------------------------------------------------------------------------
// Client wrappers via a fake grpc.ClientConnInterface.
// ---------------------------------------------------------------------------

var errConnBoom = errors.New("conn boom")

type fakeClientConn struct {
	methods     []string
	invokeErr   error
	streamErr   error
	invokeReply proto.Message // merged into the reply argument when set
}

func (f *fakeClientConn) Invoke(_ context.Context, method string, _, reply any, _ ...grpc.CallOption) error {
	f.methods = append(f.methods, method)
	if f.invokeErr != nil {
		return f.invokeErr
	}
	if f.invokeReply != nil {
		msg, ok := reply.(proto.Message)
		if !ok {
			return errors.New("reply is not a proto.Message")
		}
		proto.Merge(msg, f.invokeReply)
	}
	return nil
}

func (f *fakeClientConn) NewStream(_ context.Context, _ *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	f.methods = append(f.methods, method)
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	return &fakeClientStream{recvReply: f.invokeReply}, nil
}

type fakeClientStream struct {
	recvReply proto.Message
	sent      []proto.Message
	closed    bool
}

func (s *fakeClientStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *fakeClientStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *fakeClientStream) CloseSend() error             { s.closed = true; return nil }
func (s *fakeClientStream) Context() context.Context     { return context.Background() }

func (s *fakeClientStream) SendMsg(m any) error {
	msg, ok := m.(proto.Message)
	if !ok {
		return errors.New("sent message is not a proto.Message")
	}
	s.sent = append(s.sent, proto.Clone(msg))
	return nil
}

func (s *fakeClientStream) RecvMsg(m any) error {
	if s.recvReply == nil {
		return errors.New("no reply configured")
	}
	msg, ok := m.(proto.Message)
	if !ok {
		return errors.New("received message is not a proto.Message")
	}
	proto.Merge(msg, s.recvReply)
	return nil
}

func TestNewCollectorServiceClient_UnaryCalls(t *testing.T) {
	ctx := context.Background()

	t.Run("heartbeat success", func(t *testing.T) {
		conn := &fakeClientConn{invokeReply: &HeartbeatResponse{ServerTime: timestamppb.New(fixedTime)}}
		client := NewCollectorServiceClient(conn)

		resp, err := client.Heartbeat(ctx, &HeartbeatRequest{AgentId: "a-1"})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, fixedTime.Unix(), resp.GetServerTime().GetSeconds())
		assert.Equal(t, []string{"/kite.v1.CollectorService/Heartbeat"}, conn.methods)
	})

	t.Run("enroll success", func(t *testing.T) {
		conn := &fakeClientConn{invokeReply: &EnrollResponse{Status: "enrolled", CertificateExpiresAt: 42}}
		client := NewCollectorServiceClient(conn)

		resp, err := client.Enroll(ctx, &EnrollRequest{AgentId: "a-2"})
		require.NoError(t, err)
		assert.Equal(t, "enrolled", resp.GetStatus())
		assert.Equal(t, int64(42), resp.GetCertificateExpiresAt())
		assert.Equal(t, []string{"/kite.v1.CollectorService/Enroll"}, conn.methods)
	})

	t.Run("renew success", func(t *testing.T) {
		conn := &fakeClientConn{invokeReply: &RenewResponse{Status: "renewed"}}
		client := NewCollectorServiceClient(conn)

		resp, err := client.RenewCertificate(ctx, &RenewRequest{AgentId: "a-3"})
		require.NoError(t, err)
		assert.Equal(t, "renewed", resp.GetStatus())
		assert.Equal(t, []string{"/kite.v1.CollectorService/RenewCertificate"}, conn.methods)
	})

	t.Run("invoke errors propagate", func(t *testing.T) {
		conn := &fakeClientConn{invokeErr: errConnBoom}
		client := NewCollectorServiceClient(conn)

		hb, err := client.Heartbeat(ctx, &HeartbeatRequest{})
		assert.Nil(t, hb)
		assert.ErrorIs(t, err, errConnBoom)

		enroll, err := client.Enroll(ctx, &EnrollRequest{})
		assert.Nil(t, enroll)
		assert.ErrorIs(t, err, errConnBoom)

		renew, err := client.RenewCertificate(ctx, &RenewRequest{})
		assert.Nil(t, renew)
		assert.ErrorIs(t, err, errConnBoom)
	})
}

func TestNewCollectorServiceClient_StreamingCalls(t *testing.T) {
	ctx := context.Background()

	t.Run("report machines success", func(t *testing.T) {
		conn := &fakeClientConn{invokeReply: &ReportResponse{Accepted: 7, Rejected: 1}}
		client := NewCollectorServiceClient(conn)

		stream, err := client.ReportMachines(ctx)
		require.NoError(t, err)
		require.NotNil(t, stream)
		assert.Equal(t, []string{"/kite.v1.CollectorService/ReportMachines"}, conn.methods)

		require.NoError(t, stream.Send(&MachineSnapshot{Hostname: "h-1"}))
		resp, err := stream.CloseAndRecv()
		require.NoError(t, err)
		assert.Equal(t, int32(7), resp.GetAccepted())
		assert.Equal(t, int32(1), resp.GetRejected())
	})

	t.Run("report findings success", func(t *testing.T) {
		conn := &fakeClientConn{invokeReply: &ReportResponse{Accepted: 2}}
		client := NewCollectorServiceClient(conn)

		stream, err := client.ReportFindings(ctx)
		require.NoError(t, err)
		require.NotNil(t, stream)
		assert.Equal(t, []string{"/kite.v1.CollectorService/ReportFindings"}, conn.methods)

		require.NoError(t, stream.Send(&ConfigFinding{FindingId: "f-1"}))
		resp, err := stream.CloseAndRecv()
		require.NoError(t, err)
		assert.Equal(t, int32(2), resp.GetAccepted())
		assert.Equal(t, int32(0), resp.GetRejected())
	})

	t.Run("new stream errors propagate", func(t *testing.T) {
		conn := &fakeClientConn{streamErr: errConnBoom}
		client := NewCollectorServiceClient(conn)

		machineStream, err := client.ReportMachines(ctx)
		assert.Nil(t, machineStream)
		assert.ErrorIs(t, err, errConnBoom)

		findingStream, err := client.ReportFindings(ctx)
		assert.Nil(t, findingStream)
		assert.ErrorIs(t, err, errConnBoom)
	})
}

// ---------------------------------------------------------------------------
// Server registration, service descriptor, and generated handlers.
// ---------------------------------------------------------------------------

type fakeRegistrar struct {
	desc *grpc.ServiceDesc
	impl any
}

func (r *fakeRegistrar) RegisterService(desc *grpc.ServiceDesc, impl any) {
	r.desc = desc
	r.impl = impl
}

// stubCollectorServer overrides every RPC with deterministic responses.
type stubCollectorServer struct {
	UnimplementedCollectorServiceServer
	gotHeartbeat *HeartbeatRequest
	gotEnroll    *EnrollRequest
	gotRenew     *RenewRequest
}

func (s *stubCollectorServer) Heartbeat(_ context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	s.gotHeartbeat = req
	return &HeartbeatResponse{ServerTime: timestamppb.New(fixedTime)}, nil
}

func (s *stubCollectorServer) Enroll(_ context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	s.gotEnroll = req
	return &EnrollResponse{Status: "enrolled"}, nil
}

func (s *stubCollectorServer) RenewCertificate(_ context.Context, req *RenewRequest) (*RenewResponse, error) {
	s.gotRenew = req
	return &RenewResponse{Status: "renewed"}, nil
}

func (s *stubCollectorServer) ReportMachines(stream grpc.ClientStreamingServer[MachineSnapshot, ReportResponse]) error {
	if err := stream.SendAndClose(&ReportResponse{Accepted: 3}); err != nil {
		return fmt.Errorf("send and close machines: %w", err)
	}
	return nil
}

func (s *stubCollectorServer) ReportFindings(stream grpc.ClientStreamingServer[ConfigFinding, ReportResponse]) error {
	if err := stream.SendAndClose(&ReportResponse{Accepted: 5, Rejected: 2}); err != nil {
		return fmt.Errorf("send and close findings: %w", err)
	}
	return nil
}

func TestRegisterCollectorServiceServer(t *testing.T) {
	reg := &fakeRegistrar{}
	srv := &stubCollectorServer{}

	RegisterCollectorServiceServer(reg, srv)

	require.NotNil(t, reg.desc)
	assert.Equal(t, "kite.v1.CollectorService", reg.desc.ServiceName)
	assert.Same(t, srv, reg.impl)
}

func TestServiceDesc_ExactShape(t *testing.T) {
	assert.Equal(t, "kite.v1.CollectorService", CollectorService_ServiceDesc.ServiceName)
	assert.Equal(t, "api/grpc/proto/kite/v1/collector.proto", CollectorService_ServiceDesc.Metadata)

	require.Len(t, CollectorService_ServiceDesc.Methods, 3)
	assert.Equal(t, "Heartbeat", CollectorService_ServiceDesc.Methods[0].MethodName)
	assert.Equal(t, "Enroll", CollectorService_ServiceDesc.Methods[1].MethodName)
	assert.Equal(t, "RenewCertificate", CollectorService_ServiceDesc.Methods[2].MethodName)

	require.Len(t, CollectorService_ServiceDesc.Streams, 2)
	assert.Equal(t, "ReportMachines", CollectorService_ServiceDesc.Streams[0].StreamName)
	assert.True(t, CollectorService_ServiceDesc.Streams[0].ClientStreams)
	assert.False(t, CollectorService_ServiceDesc.Streams[0].ServerStreams)
	assert.Equal(t, "ReportFindings", CollectorService_ServiceDesc.Streams[1].StreamName)
	assert.True(t, CollectorService_ServiceDesc.Streams[1].ClientStreams)
	assert.False(t, CollectorService_ServiceDesc.Streams[1].ServerStreams)

	assert.Equal(t, "/kite.v1.CollectorService/ReportMachines", CollectorService_ReportMachines_FullMethodName)
	assert.Equal(t, "/kite.v1.CollectorService/ReportFindings", CollectorService_ReportFindings_FullMethodName)
	assert.Equal(t, "/kite.v1.CollectorService/Heartbeat", CollectorService_Heartbeat_FullMethodName)
	assert.Equal(t, "/kite.v1.CollectorService/Enroll", CollectorService_Enroll_FullMethodName)
	assert.Equal(t, "/kite.v1.CollectorService/RenewCertificate", CollectorService_RenewCertificate_FullMethodName)
}

// decodeInto returns a dec func (as passed by grpc-go to unary handlers) that
// merges src into the freshly allocated request message.
func decodeInto(src proto.Message) func(any) error {
	return func(m any) error {
		msg, ok := m.(proto.Message)
		if !ok {
			return errors.New("decode target is not a proto.Message")
		}
		proto.Merge(msg, src)
		return nil
	}
}

func failDecode(any) error { return errConnBoom }

func TestUnaryHandlers_DirectDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("heartbeat", func(t *testing.T) {
		srv := &stubCollectorServer{}
		got, err := _CollectorService_Heartbeat_Handler(
			srv, ctx, decodeInto(&HeartbeatRequest{AgentId: "hb-agent"}), nil)
		require.NoError(t, err)
		resp, ok := got.(*HeartbeatResponse)
		require.True(t, ok)
		assert.Equal(t, fixedTime.Unix(), resp.GetServerTime().GetSeconds())
		require.NotNil(t, srv.gotHeartbeat)
		assert.Equal(t, "hb-agent", srv.gotHeartbeat.GetAgentId())
	})

	t.Run("enroll", func(t *testing.T) {
		srv := &stubCollectorServer{}
		got, err := _CollectorService_Enroll_Handler(
			srv, ctx, decodeInto(&EnrollRequest{AgentId: "enroll-agent"}), nil)
		require.NoError(t, err)
		resp, ok := got.(*EnrollResponse)
		require.True(t, ok)
		assert.Equal(t, "enrolled", resp.GetStatus())
		require.NotNil(t, srv.gotEnroll)
		assert.Equal(t, "enroll-agent", srv.gotEnroll.GetAgentId())
	})

	t.Run("renew", func(t *testing.T) {
		srv := &stubCollectorServer{}
		got, err := _CollectorService_RenewCertificate_Handler(
			srv, ctx, decodeInto(&RenewRequest{AgentId: "renew-agent"}), nil)
		require.NoError(t, err)
		resp, ok := got.(*RenewResponse)
		require.True(t, ok)
		assert.Equal(t, "renewed", resp.GetStatus())
		require.NotNil(t, srv.gotRenew)
		assert.Equal(t, "renew-agent", srv.gotRenew.GetAgentId())
	})
}

func TestUnaryHandlers_DecodeErrors(t *testing.T) {
	ctx := context.Background()
	srv := &stubCollectorServer{}

	got, err := _CollectorService_Heartbeat_Handler(srv, ctx, failDecode, nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, errConnBoom)

	got, err = _CollectorService_Enroll_Handler(srv, ctx, failDecode, nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, errConnBoom)

	got, err = _CollectorService_RenewCertificate_Handler(srv, ctx, failDecode, nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, errConnBoom)
}

func TestUnaryHandlers_InterceptorPath(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		fullMethod string
		invoke     func(srv CollectorServiceServer, interceptor grpc.UnaryServerInterceptor) (any, error)
		verify     func(t *testing.T, got any)
	}{
		{
			name:       "heartbeat",
			fullMethod: "/kite.v1.CollectorService/Heartbeat",
			invoke: func(srv CollectorServiceServer, interceptor grpc.UnaryServerInterceptor) (any, error) {
				return _CollectorService_Heartbeat_Handler(
					srv, ctx, decodeInto(&HeartbeatRequest{AgentId: "i-1"}), interceptor)
			},
			verify: func(t *testing.T, got any) {
				t.Helper()
				resp, ok := got.(*HeartbeatResponse)
				require.True(t, ok)
				assert.Equal(t, fixedTime.Unix(), resp.GetServerTime().GetSeconds())
			},
		},
		{
			name:       "enroll",
			fullMethod: "/kite.v1.CollectorService/Enroll",
			invoke: func(srv CollectorServiceServer, interceptor grpc.UnaryServerInterceptor) (any, error) {
				return _CollectorService_Enroll_Handler(
					srv, ctx, decodeInto(&EnrollRequest{AgentId: "i-2"}), interceptor)
			},
			verify: func(t *testing.T, got any) {
				t.Helper()
				resp, ok := got.(*EnrollResponse)
				require.True(t, ok)
				assert.Equal(t, "enrolled", resp.GetStatus())
			},
		},
		{
			name:       "renew",
			fullMethod: "/kite.v1.CollectorService/RenewCertificate",
			invoke: func(srv CollectorServiceServer, interceptor grpc.UnaryServerInterceptor) (any, error) {
				return _CollectorService_RenewCertificate_Handler(
					srv, ctx, decodeInto(&RenewRequest{AgentId: "i-3"}), interceptor)
			},
			verify: func(t *testing.T, got any) {
				t.Helper()
				resp, ok := got.(*RenewResponse)
				require.True(t, ok)
				assert.Equal(t, "renewed", resp.GetStatus())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &stubCollectorServer{}
			var sawFullMethod string
			interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				sawFullMethod = info.FullMethod
				assert.Same(t, srv, info.Server)
				return handler(ctx, req)
			}

			got, err := tc.invoke(srv, interceptor)
			require.NoError(t, err)
			assert.Equal(t, tc.fullMethod, sawFullMethod)
			tc.verify(t, got)
		})
	}
}

type fakeServerStream struct {
	sent []proto.Message
}

func (s *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeServerStream) SetTrailer(metadata.MD)       {}
func (s *fakeServerStream) Context() context.Context     { return context.Background() }

func (s *fakeServerStream) SendMsg(m any) error {
	msg, ok := m.(proto.Message)
	if !ok {
		return errors.New("sent message is not a proto.Message")
	}
	s.sent = append(s.sent, proto.Clone(msg))
	return nil
}

func (s *fakeServerStream) RecvMsg(any) error { return errors.New("no inbound messages") }

func TestStreamHandlers_DispatchToServer(t *testing.T) {
	t.Run("report machines", func(t *testing.T) {
		stream := &fakeServerStream{}
		err := _CollectorService_ReportMachines_Handler(&stubCollectorServer{}, stream)
		require.NoError(t, err)
		require.Len(t, stream.sent, 1)
		resp, ok := stream.sent[0].(*ReportResponse)
		require.True(t, ok)
		assert.Equal(t, int32(3), resp.GetAccepted())
		assert.Equal(t, int32(0), resp.GetRejected())
	})

	t.Run("report findings", func(t *testing.T) {
		stream := &fakeServerStream{}
		err := _CollectorService_ReportFindings_Handler(&stubCollectorServer{}, stream)
		require.NoError(t, err)
		require.Len(t, stream.sent, 1)
		resp, ok := stream.sent[0].(*ReportResponse)
		require.True(t, ok)
		assert.Equal(t, int32(5), resp.GetAccepted())
		assert.Equal(t, int32(2), resp.GetRejected())
	})
}

// ---------------------------------------------------------------------------
// Unmarshal edge cases.
// ---------------------------------------------------------------------------

func TestUnmarshal_EmptyBytesYieldsZeroMessage(t *testing.T) {
	got := &HeartbeatRequest{}
	require.NoError(t, proto.Unmarshal(nil, got))
	assert.Equal(t, "", got.GetAgentId())
	assert.Equal(t, int64(0), got.GetUptimeSeconds())
}

func TestUnmarshal_MalformedBytesFails(t *testing.T) {
	// Field 1, wire type 2 (length-delimited) claiming 100 bytes with none present.
	malformed := []byte{0x0A, 0x64}
	err := proto.Unmarshal(malformed, &HeartbeatRequest{})
	require.Error(t, err)
}
