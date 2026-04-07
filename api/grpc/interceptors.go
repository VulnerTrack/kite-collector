package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryRecoveryInterceptor returns a gRPC unary server interceptor that
// recovers panics in handlers, logs the stack trace, increments the
// counter, and returns codes.Internal to the client.
func UnaryRecoveryInterceptor(counter *prometheus.CounterVec) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				slog.Error("panic recovered in gRPC unary handler",
					"component", "grpc",
					"method", info.FullMethod,
					"error", fmt.Sprint(r),
					"stack_trace", stack,
				)
				if counter != nil {
					counter.With(prometheus.Labels{"component": "grpc"}).Inc()
				}
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// StreamRecoveryInterceptor returns a gRPC stream server interceptor that
// recovers panics in stream handlers.
func StreamRecoveryInterceptor(counter *prometheus.CounterVec) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				slog.Error("panic recovered in gRPC stream handler",
					"component", "grpc",
					"method", info.FullMethod,
					"error", fmt.Sprint(r),
					"stack_trace", stack,
				)
				if counter != nil {
					counter.With(prometheus.Labels{"component": "grpc"}).Inc()
				}
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}
