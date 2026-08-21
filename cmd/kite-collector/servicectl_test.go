package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kardianos/service"
)

// fakeSvc implements serviceController with scripted results and call
// counters.
type fakeSvc struct {
	status     service.Status
	statusErr  error
	startErr   error
	stopErr    error
	restartErr error

	startCalls   int
	stopCalls    int
	restartCalls int
}

func (f *fakeSvc) Start() error { f.startCalls++; return f.startErr }
func (f *fakeSvc) Stop() error  { f.stopCalls++; return f.stopErr }
func (f *fakeSvc) Restart() error {
	f.restartCalls++
	return f.restartErr
}
func (f *fakeSvc) Status() (service.Status, error) { return f.status, f.statusErr }

// launchd5Err mirrors the exact shape kardianos surfaces on modern
// macOS: legacy launchctl load/unload collapsing every state mismatch
// into the catch-all code 5.
func launchd5Err(verb string) error {
	return fmt.Errorf(
		"\"launchctl\" failed with stderr: %s failed: 5: Input/output error\n"+
			"Try running `launchctl bootstrap` as root for richer errors.", verb)
}

// noKickstart fails the test if the kickstart fallback fires when it
// must not.
func noKickstart(t *testing.T) func(string) error {
	t.Helper()
	return func(target string) error {
		t.Fatalf("kickstart must not be called (target %q)", target)
		return nil
	}
}

func TestStartAlreadyRunningIsIdempotent(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning}
	outcome, err := ensureServiceState(svc, "start", "darwin", false, noKickstart(t))
	if err != nil {
		t.Fatalf("already-running start must succeed: %v", err)
	}
	if outcome != outcomeAlreadyRunning {
		t.Fatalf("outcome=%q", outcome)
	}
	if svc.startCalls != 0 {
		t.Fatal("must not call Start on a running service")
	}
}

func TestStartNotInstalledExplainsInstall(t *testing.T) {
	svc := &fakeSvc{statusErr: service.ErrNotInstalled}
	_, err := ensureServiceState(svc, "start", "linux", false, noKickstart(t))
	if err == nil || !strings.Contains(err.Error(), "sudo kite-collector install") {
		t.Fatalf("err=%v", err)
	}
	_, err = ensureServiceState(svc, "start", "linux", true, noKickstart(t))
	if err == nil || !strings.Contains(err.Error(), "install --user") {
		t.Fatalf("user-mode hint missing: %v", err)
	}
}

func TestStartStoppedService(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped}
	outcome, err := ensureServiceState(svc, "start", "linux", false, noKickstart(t))
	if err != nil || outcome != outcomeStarted {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if svc.startCalls != 1 {
		t.Fatalf("startCalls=%d", svc.startCalls)
	}
}

func TestStartLaunchd5KickstartsLoadedIdleJob(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped, startErr: launchd5Err("Load")}
	var target string
	outcome, err := ensureServiceState(svc, "start", "darwin", false,
		func(tg string) error { target = tg; return nil })
	if err != nil {
		t.Fatalf("kickstart fallback must succeed: %v", err)
	}
	if outcome != outcomeKickstarted {
		t.Fatalf("outcome=%q", outcome)
	}
	if target != "system/kite-collector" {
		t.Fatalf("target=%q", target)
	}
}

func TestStartLaunchd5UserModeTargetsGUIDomain(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped, startErr: launchd5Err("Load")}
	var target string
	_, err := ensureServiceState(svc, "start", "darwin", true,
		func(tg string) error { target = tg; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, "gui/") || !strings.HasSuffix(target, "/kite-collector") {
		t.Fatalf("target=%q", target)
	}
}

func TestStartLaunchd5KickstartFailureExplainsCode5(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped, startErr: launchd5Err("Load")}
	_, err := ensureServiceState(svc, "start", "darwin", false,
		func(string) error { return errors.New("kickstart denied") })
	if err == nil {
		t.Fatal("must surface an error when kickstart also fails")
	}
	for _, must := range []string{"error 5", "ALREADY", "launchctl print system/kite-collector"} {
		if !strings.Contains(err.Error(), must) {
			t.Fatalf("decorated error missing %q: %v", must, err)
		}
	}
}

func TestStartLaunchd5NotInterceptedOffDarwin(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped, startErr: launchd5Err("Load")}
	_, err := ensureServiceState(svc, "start", "linux", false, noKickstart(t))
	if err == nil || !strings.Contains(err.Error(), "start service:") {
		t.Fatalf("non-darwin must pass the error through wrapped: %v", err)
	}
}

func TestStopNotInstalledIsIdempotent(t *testing.T) {
	svc := &fakeSvc{statusErr: service.ErrNotInstalled}
	outcome, err := ensureServiceState(svc, "stop", "linux", false, noKickstart(t))
	if err != nil || outcome != outcomeNotInstalled {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if svc.stopCalls != 0 {
		t.Fatal("must not call Stop when not installed")
	}
}

func TestStopRunningService(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning}
	outcome, err := ensureServiceState(svc, "stop", "linux", false, noKickstart(t))
	if err != nil || outcome != outcomeStopped {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
}

func TestStopLaunchd5OnIdleJobIsAlreadyStopped(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped, stopErr: launchd5Err("Unload")}
	outcome, err := ensureServiceState(svc, "stop", "darwin", false, noKickstart(t))
	if err != nil {
		t.Fatalf("unload error 5 on idle job must be idempotent success: %v", err)
	}
	if outcome != outcomeAlreadyStopped {
		t.Fatalf("outcome=%q", outcome)
	}
}

func TestStopLaunchd5OnRunningJobStaysAnError(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning, stopErr: launchd5Err("Unload")}
	_, err := ensureServiceState(svc, "stop", "darwin", false, noKickstart(t))
	if err == nil || !strings.Contains(err.Error(), "error 5") {
		t.Fatalf("err=%v", err)
	}
}

func TestRestartRunningService(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning}
	outcome, err := ensureServiceState(svc, "restart", "linux", false, noKickstart(t))
	if err != nil || outcome != outcomeRestarted {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if svc.restartCalls != 1 {
		t.Fatalf("restartCalls=%d", svc.restartCalls)
	}
}

func TestRestartIdleServiceBecomesStart(t *testing.T) {
	svc := &fakeSvc{status: service.StatusStopped}
	outcome, err := ensureServiceState(svc, "restart", "linux", false, noKickstart(t))
	if err != nil || outcome != outcomeStartedWasIdle {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if svc.restartCalls != 0 || svc.startCalls != 1 {
		t.Fatalf("restartCalls=%d startCalls=%d", svc.restartCalls, svc.startCalls)
	}
}

func TestRestartNotInstalledExplainsInstall(t *testing.T) {
	svc := &fakeSvc{statusErr: service.ErrNotInstalled}
	_, err := ensureServiceState(svc, "restart", "linux", false, noKickstart(t))
	if err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("err=%v", err)
	}
}

func TestUnknownActionErrors(t *testing.T) {
	svc := &fakeSvc{status: service.StatusRunning}
	if _, err := ensureServiceState(svc, "frobnicate", "linux", false, noKickstart(t)); err == nil {
		t.Fatal("unknown action must error")
	}
}

func TestIsLaunchdError5Discrimination(t *testing.T) {
	if !isLaunchdError5(launchd5Err("Load")) || !isLaunchdError5(launchd5Err("Boot-out")) {
		t.Fatal("must recognise launchd code-5 shapes")
	}
	if isLaunchdError5(errors.New("open /etc/foo: input/output error")) {
		t.Fatal("plain EIO from other sources must not match")
	}
	if isLaunchdError5(nil) {
		t.Fatal("nil must not match")
	}
}
