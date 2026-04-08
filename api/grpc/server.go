package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// Server implements the kite.v1.CollectorService gRPC service. It receives
// streamed asset snapshots from remote agents, converts them to domain
// model.Asset values, and persists them through the store.Store interface.
type Server struct {
	kitev1.UnimplementedCollectorServiceServer
	store           store.Store
	logger          *slog.Logger
	grpc            *grpc.Server
	panicsRecovered *prometheus.CounterVec
	tlsConfig       *tls.Config
	addr            string
}

// SetPanicsRecovered sets the Prometheus counter used by the gRPC recovery
// interceptors to track recovered panics.
func (s *Server) SetPanicsRecovered(c *prometheus.CounterVec) {
	s.panicsRecovered = c
}

// New creates a Server that will listen on addr when Serve is called. The
// supplied store is used for all persistence operations. If logger is nil a
// default slog.Logger is used.
func New(addr string, st store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		addr:   addr,
		store:  st,
		logger: logger,
	}
}

// ConfigureMTLS sets up mutual TLS on the server. The server presents its
// own certificate and requires valid client certificates signed by the
// provided CA.
func (s *Server) ConfigureMTLS(tlsCfg config.TLSConfig) error {
	if tlsCfg.CertFile == "" || tlsCfg.KeyFile == "" {
		return fmt.Errorf("mTLS requires both cert_file and key_file")
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load server TLS keypair: %w", err)
	}

	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	if tlsCfg.CAFile != "" {
		caPEM, readErr := os.ReadFile(tlsCfg.CAFile)
		if readErr != nil {
			return fmt.Errorf("read CA file: %w", readErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("CA file contains no valid certificates")
		}
		tc.ClientCAs = pool
	}

	s.tlsConfig = tc
	s.logger.Info("mTLS configured for gRPC server")
	return nil
}

// Serve starts the gRPC listener on the configured address. It blocks until
// the server is stopped or an error occurs.
func (s *Server) Serve() error {
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", s.addr)
	if err != nil {
		return err
	}

	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryRecoveryInterceptor(s.panicsRecovered)),
		grpc.ChainStreamInterceptor(StreamRecoveryInterceptor(s.panicsRecovered)),
	}

	if s.tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(s.tlsConfig)))
		s.logger.Info("gRPC server using mTLS", "addr", s.addr)
	} else {
		s.logger.Warn("gRPC server running WITHOUT TLS — not recommended for production", "addr", s.addr)
	}

	s.grpc = grpc.NewServer(opts...)
	kitev1.RegisterCollectorServiceServer(s.grpc, s)
	s.logger.Info("gRPC server listening", "addr", s.addr)
	return s.grpc.Serve(lis)
}

// Stop gracefully shuts down the gRPC server, draining in-flight RPCs.
func (s *Server) Stop() {
	if s.grpc != nil {
		s.grpc.GracefulStop()
	}
}

// ReportAssets implements kite.v1.CollectorService.ReportAssets. It consumes
// a client stream of AssetSnapshot messages, upserting each into the store
// (along with any attached software inventory), and returns a summary of
// accepted vs rejected snapshots when the stream ends.
func (s *Server) ReportAssets(stream kitev1.CollectorService_ReportAssetsServer) error {
	ctx := stream.Context()
	var accepted, rejected int32

	for {
		snapshot, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&kitev1.ReportResponse{
				Accepted: accepted,
				Rejected: rejected,
			})
		}
		if err != nil {
			return err
		}

		asset := snapshotToAsset(snapshot)
		if upsertErr := s.store.UpsertAsset(ctx, asset); upsertErr != nil {
			s.logger.Warn("gRPC: failed to upsert asset", "hostname", snapshot.Hostname, "error", upsertErr)
			rejected++
			continue
		}

		// Upsert software if present.
		if len(snapshot.Software) > 0 {
			sw := make([]model.InstalledSoftware, 0, len(snapshot.Software))
			for _, pkg := range snapshot.Software {
				sw = append(sw, model.InstalledSoftware{
					ID:             uuid.Must(uuid.NewV7()),
					AssetID:        asset.ID,
					SoftwareName:   pkg.Name,
					Version:        pkg.Version,
					Vendor:         pkg.Vendor,
					CPE23:          pkg.Cpe23,
					PackageManager: pkg.PackageManager,
				})
			}
			if swErr := s.store.UpsertSoftware(ctx, asset.ID, sw); swErr != nil {
				s.logger.Warn("gRPC: failed to upsert software", "asset_id", asset.ID, "error", swErr)
			}
		}

		accepted++
	}
}

// ReportFindings implements kite.v1.CollectorService.ReportFindings.
func (s *Server) ReportFindings(stream kitev1.CollectorService_ReportFindingsServer) error {
	var accepted, rejected int32
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&kitev1.ReportResponse{
				Accepted: accepted,
				Rejected: rejected,
			})
		}
		if err != nil {
			return err
		}
		// Findings storage is handled by the audit subsystem; this RPC
		// accepts and acknowledges them.
		accepted++
	}
}

// Heartbeat implements kite.v1.CollectorService.Heartbeat. It returns the
// current server time so agents can verify connectivity and clock drift.
func (s *Server) Heartbeat(ctx context.Context, req *kitev1.HeartbeatRequest) (*kitev1.HeartbeatResponse, error) {
	s.logger.Debug("gRPC: heartbeat received", "agent_id", req.AgentId)
	return &kitev1.HeartbeatResponse{
		ServerTime: timestamppb.Now(),
	}, nil
}

// Enroll implements kite.v1.CollectorService.Enroll. This is a placeholder
// server-side implementation; the full enrollment logic is defined by
// RFC-0063 on the server side.
func (s *Server) Enroll(ctx context.Context, req *kitev1.EnrollRequest) (*kitev1.EnrollResponse, error) {
	s.logger.Info("gRPC: enrollment request",
		"agent_id", req.AgentId,
		"hostname", req.Hostname,
		"os", req.OsFamily,
	)
	// Server-side enrollment logic (RFC-0063) validates the token,
	// signs a client certificate, and returns it. This placeholder
	// returns "pending" for agents where approval is manual.
	return nil, status.Errorf(codes.Unimplemented, "enrollment handled by fleet manager (RFC-0063)")
}

// RenewCertificate implements kite.v1.CollectorService.RenewCertificate.
func (s *Server) RenewCertificate(ctx context.Context, req *kitev1.RenewRequest) (*kitev1.RenewResponse, error) {
	s.logger.Info("gRPC: certificate renewal request", "agent_id", req.AgentId)
	return nil, status.Errorf(codes.Unimplemented, "certificate renewal handled by fleet manager (RFC-0063)")
}

// snapshotToAsset converts a protobuf AssetSnapshot into a domain model.Asset
// with sensible defaults for missing fields.
func snapshotToAsset(s *kitev1.AssetSnapshot) model.Asset {
	now := time.Now().UTC()
	a := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        s.Hostname,
		AssetType:       model.AssetType(s.AssetType),
		OSFamily:        s.OsFamily,
		OSVersion:       s.OsVersion,
		Environment:     s.Environment,
		Owner:           s.Owner,
		Criticality:     s.Criticality,
		Tags:            s.TagsJson,
		DiscoverySource: s.DiscoverySource,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
	if !a.AssetType.Valid() {
		a.AssetType = model.AssetTypeServer
	}
	if a.DiscoverySource == "" {
		a.DiscoverySource = "grpc_agent"
	}
	a.ComputeNaturalKey()
	return a
}
