// Package grpcapi provides a gRPC server stub for Phase 3 high-throughput
// agent streaming. In Phase 3 the REST API will be complemented by a gRPC
// endpoint that allows agents to stream asset snapshots in real time, reducing
// per-request overhead for large fleets.
//
// Planned proto definition (api/proto/kite/v1/collector.proto):
//
//	syntax = "proto3";
//	package kite.v1;
//
//	import "google/protobuf/timestamp.proto";
//
//	service CollectorService {
//	    // ReportAssets streams asset snapshots from agents to the server.
//	    rpc ReportAssets(stream AssetSnapshot) returns (ReportResponse);
//
//	    // Heartbeat allows agents to signal liveness without a full report.
//	    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
//	}
//
//	message AssetSnapshot {
//	    string hostname      = 1;
//	    string asset_type    = 2;
//	    string os_family     = 3;
//	    string os_version    = 4;
//	    string environment   = 5;
//	    string owner         = 6;
//	    string criticality   = 7;
//	    string tags_json     = 8;
//	    google.protobuf.Timestamp collected_at = 9;
//	    repeated InstalledPackage software     = 10;
//	}
//
//	message InstalledPackage {
//	    string name            = 1;
//	    string version         = 2;
//	    string vendor          = 3;
//	    string cpe23           = 4;
//	    string package_manager = 5;
//	}
//
//	message ReportResponse {
//	    int32 accepted = 1;
//	    int32 rejected = 2;
//	}
//
//	message HeartbeatRequest {
//	    string agent_id = 1;
//	}
//
//	message HeartbeatResponse {
//	    google.protobuf.Timestamp server_time = 1;
//	}
package grpcapi

import "log/slog"

// Server is a placeholder for the Phase 3 gRPC streaming endpoint. Once the
// proto definition above is finalised and compiled, Server will embed the
// generated UnimplementedCollectorServiceServer and implement ReportAssets and
// Heartbeat.
type Server struct {
	logger *slog.Logger
	addr   string
}

// New creates a Server that will listen on addr when Serve is called. If
// logger is nil a default slog.Logger is used.
func New(addr string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		addr:   addr,
		logger: logger,
	}
}

// Serve starts the gRPC listener. This is a stub that logs a message and
// returns immediately; the real implementation will be added in Phase 3.
func (s *Server) Serve() error {
	s.logger.Warn("gRPC server not yet implemented", "addr", s.addr)
	return nil
}
