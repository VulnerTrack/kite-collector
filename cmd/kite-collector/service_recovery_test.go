package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kardianos/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedAgentFailureRequestsProcessRestart(t *testing.T) {
	exitCode := 0
	runManagedAgent(context.Background(), func(context.Context) error {
		return errors.New("database temporarily unavailable")
	}, func(code int) { exitCode = code })
	assert.Equal(t, 1, exitCode)
}

func TestManagedAgentUnexpectedCleanExitRequestsProcessRestart(t *testing.T) {
	exitCode := 0
	runManagedAgent(context.Background(), func(context.Context) error {
		return nil
	}, func(code int) { exitCode = code })
	assert.Equal(t, 1, exitCode, "a live service cannot silently lose its agent")
}

func TestManagedAgentOperatorStopDoesNotRequestRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runManagedAgent(ctx, func(ctx context.Context) error {
		cancel()
		return ctx.Err()
	}, func(code int) { t.Fatalf("explicit stop requested process restart: %d", code) })
}

func TestManagedAgentUpgradeShutdownDoesNotRequestFailureRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runManagedAgent(ctx, func(context.Context) error {
		cancel()
		return nil
	}, func(code int) { t.Fatalf("upgrade shutdown reported as failure: %d", code) })
}

func TestStartCollectorServicePropagatesFailure(t *testing.T) {
	startErr := errors.New("service manager rejected startup")
	svc := &fakeSvc{status: service.StatusStopped, startErr: startErr}
	var out bytes.Buffer
	err := startCollectorService(&out, svc, false)
	require.ErrorIs(t, err, startErr)
	assert.Equal(t, 1, svc.startCalls)
	assert.Contains(t, out.String(), "service start failed")
}

func TestStartCollectorServiceAcceptsAlreadyRunning(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning}
	var out bytes.Buffer
	require.NoError(t, startCollectorService(&out, svc, false))
	assert.Zero(t, svc.startCalls)
}
