package grpcapi

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnaryRecoveryInterceptor_CatchesPanic(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_grpc_panics",
	}, []string{"component"})

	interceptor := UnaryRecoveryInterceptor(counter)

	panickingHandler := func(ctx context.Context, req any) (any, error) {
		panic("grpc panic")
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(context.Background(), nil, info, panickingHandler)

	assert.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "grpc"}))
	assert.Equal(t, float64(1), val)
}

func TestUnaryRecoveryInterceptor_NoPanic(t *testing.T) {
	interceptor := UnaryRecoveryInterceptor(nil)

	normalHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(context.Background(), nil, info, normalHandler)

	assert.Equal(t, "ok", resp)
	assert.NoError(t, err)
}

// mockServerStream is a minimal mock for testing stream interceptors.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context { return m.ctx }

func TestStreamRecoveryInterceptor_CatchesPanic(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_grpc_stream_panics",
	}, []string{"component"})

	interceptor := StreamRecoveryInterceptor(counter)

	panickingHandler := func(srv any, stream grpc.ServerStream) error {
		panic("stream panic")
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &mockServerStream{ctx: context.Background()}

	err := interceptor(nil, stream, info, panickingHandler)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "grpc"}))
	assert.Equal(t, float64(1), val)
}

func TestStreamRecoveryInterceptor_NoPanic(t *testing.T) {
	interceptor := StreamRecoveryInterceptor(nil)

	normalHandler := func(srv any, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &mockServerStream{ctx: context.Background()}

	err := interceptor(nil, stream, info, normalHandler)
	assert.NoError(t, err)
}
