package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryRecoveryInterceptor returns a gRPC unary server interceptor that
// recovers panics in handlers, logs the stack trace, and returns
// codes.Internal to the client.
func UnaryRecoveryInterceptor() grpc.UnaryServerInterceptor {
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
					"code", string(LogCodeInterceptorsUnaryPanicRecovered),
					"component", "grpc",
					"method", info.FullMethod,
					"error", fmt.Sprint(r),
					"stack_trace", stack,
				)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// StreamRecoveryInterceptor returns a gRPC stream server interceptor that
// recovers panics in stream handlers.
func StreamRecoveryInterceptor() grpc.StreamServerInterceptor {
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
					"code", string(LogCodeInterceptorsStreamPanicRecovered),
					"component", "grpc",
					"method", info.FullMethod,
					"error", fmt.Sprint(r),
					"stack_trace", stack,
				)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}
