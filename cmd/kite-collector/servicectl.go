package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/kardianos/service"
)

// serviceController is the narrow slice of service.Service that
// ensureServiceState drives. Narrowed for testability: fakes implement
// four methods instead of kardianos' full interface.
type serviceController interface {
	Start() error
	Stop() error
	Restart() error
	Status() (service.Status, error)
}

// Outcomes returned by ensureServiceState — human-readable fragments the
// caller prints after the service name. An "already …" outcome means the
// requested state was reached before we did anything, which is success,
// not an error: `service start` on a running service must exit 0 so
// operators (and config-management tools) can call it idempotently.
const (
	outcomeStarted        = "started"
	outcomeAlreadyRunning = "already running — nothing to do"
	outcomeKickstarted    = "started (respawned the already-loaded launchd job)"
	outcomeStopped        = "stopped"
	outcomeAlreadyStopped = "already stopped — nothing to do"
	outcomeNotInstalled   = "not installed — nothing to stop"
	outcomeRestarted      = "restarted"
	outcomeStartedWasIdle = "started (was not running)"
)

// controlInstalledService is the production entry point: runtime GOOS
// plus a real launchctl kickstart.
func controlInstalledService(svc serviceController, action string, userMode bool) (string, error) {
	return ensureServiceState(svc, action, runtime.GOOS, userMode, launchctlKickstart)
}

// ensureServiceState drives the service toward the requested action,
// tolerating already-satisfied states, and translates launchd's
// catch-all error 5 into something actionable.
//
// Background on the darwin quirk this handles: kardianos uses the
// legacy `launchctl load`/`unload` API, which since Big Sur collapses
// "already loaded", "not loaded", and a dozen unrelated failures into
// `… failed: 5: Input/output error`. The status preflight disambiguates
// the common cases before launchctl gets a chance to be cryptic, and a
// loaded-but-idle job (load says "already loaded" while no process
// runs) is respawned via `launchctl kickstart` instead of failing.
//
// goos and kickstart are seams so the darwin paths are testable on the
// Linux CI runners.
func ensureServiceState(
	svc serviceController,
	action, goos string,
	userMode bool,
	kickstart func(target string) error,
) (string, error) {
	st, stErr := svc.Status()
	notInstalled := errors.Is(stErr, service.ErrNotInstalled)

	switch action {
	case "start":
		if notInstalled {
			return "", errServiceNotInstalled(userMode)
		}
		if st == service.StatusRunning {
			return outcomeAlreadyRunning, nil
		}
		err := svc.Start()
		if err == nil {
			return outcomeStarted, nil
		}
		if goos == "darwin" && isLaunchdError5(err) {
			// The label is loaded (load said "already loaded" via
			// error 5) but the status probe saw no PID — the job is
			// loaded-but-idle. kickstart respawns it directly, no
			// bootstrap/bootout dance required.
			if kerr := kickstart(darwinServiceTarget(userMode)); kerr == nil {
				return outcomeKickstarted, nil
			}
			return "", decorateLaunchdError5(err, action, userMode)
		}
		return "", fmt.Errorf("start service: %w", err)

	case "stop":
		if notInstalled {
			return outcomeNotInstalled, nil
		}
		err := svc.Stop()
		if err == nil {
			return outcomeStopped, nil
		}
		if goos == "darwin" && isLaunchdError5(err) {
			if st != service.StatusRunning {
				// unload reported error 5 on a job with no PID: it was
				// never loaded (or already unloaded). Requested state
				// already holds.
				return outcomeAlreadyStopped, nil
			}
			return "", decorateLaunchdError5(err, action, userMode)
		}
		return "", fmt.Errorf("stop service: %w", err)

	case "restart":
		if notInstalled {
			return "", errServiceNotInstalled(userMode)
		}
		if st != service.StatusRunning {
			// Nothing running to stop — a restart of an idle service
			// is just a start.
			outcome, err := ensureServiceState(svc, "start", goos, userMode, kickstart)
			if err != nil {
				return "", err
			}
			if outcome == outcomeStarted {
				return outcomeStartedWasIdle, nil
			}
			return outcome, nil
		}
		if err := svc.Restart(); err != nil {
			if goos == "darwin" && isLaunchdError5(err) {
				return "", decorateLaunchdError5(err, action, userMode)
			}
			return "", fmt.Errorf("restart service: %w", err)
		}
		return outcomeRestarted, nil
	}
	return "", fmt.Errorf("unknown service action %q", action)
}

// errServiceNotInstalled tells the operator the one command that fixes
// the situation, in the mode they were targeting.
func errServiceNotInstalled(userMode bool) error {
	hint := "sudo kite-collector install"
	if userMode {
		hint = "kite-collector install --user"
	}
	return fmt.Errorf("service is not installed — run `%s` first", hint)
}

// isLaunchdError5 recognises launchd's catch-all failure code as
// surfaced through kardianos ("… failed with stderr: Load failed: 5:
// Input/output error"). The "failed: 5:" shape covers Load, Unload,
// Bootstrap and Boot-out variants while staying narrow enough not to
// swallow genuine I/O errors from other sources.
func isLaunchdError5(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed: 5:")
}

// decorateLaunchdError5 keeps the original error but leads with what
// code 5 almost always means, plus the command that shows the truth.
func decorateLaunchdError5(err error, action string, userMode bool) error {
	return fmt.Errorf(
		"%s service: launchd returned its catch-all error 5 (Input/output error), "+
			"which usually means the job is ALREADY in the requested state "+
			"(legacy launchctl load/unload reports both \"already loaded\" and "+
			"\"not loaded\" with this code) — check the real state with "+
			"`launchctl print %s`: %w",
		action, darwinServiceTarget(userMode), err)
}

// darwinServiceTarget is the modern launchctl domain/label pair for the
// collector job: system daemon or per-user LaunchAgent.
func darwinServiceTarget(userMode bool) string {
	if userMode {
		return fmt.Sprintf("gui/%d/%s", os.Getuid(), svcName)
	}
	return "system/" + svcName
}

// launchctlKickstart respawns an already-loaded launchd job in place.
func launchctlKickstart(target string) error {
	//#nosec G204 -- fixed executable; target is built from constants + our own uid.
	out, err := exec.CommandContext(context.Background(), "launchctl", "kickstart", target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w (%s)", target, err, trimOutput(out))
	}
	return nil
}
