package scheduled

import "context"

// Stubs for sources not yet wired. Same pattern as the other CDMS
// packages: return empty so the chain runs unconditionally.

// NewLaunchdCollector returns a stub macOS launchd collector.
//
// TODO(cdms-iter): walk these directories and parse the plists:
//   - /Library/LaunchDaemons   (system, root)
//   - /Library/LaunchAgents    (system, per-login user)
//   - /System/Library/LaunchDaemons (Apple)
//   - /System/Library/LaunchAgents
//   - ~/Library/LaunchAgents   (per-user)
//
// Extract `Label`, `Program`/`ProgramArguments`, `StartCalendarInterval`,
// `StartInterval`, `WatchPaths`. Audit-relevant fields: Disabled, UserName,
// LimitLoadToSessionType.
func NewLaunchdCollector() Collector { return sourceStub{name: "launchd-stub"} }

// NewAtCollector returns a stub `at` collector for one-shot jobs.
//
// TODO(cdms-iter): walk /var/spool/at/* (Linux) or
// /var/at/jobs/* (macOS). Format is shell-script-style.
func NewAtCollector() Collector { return sourceStub{name: "at-stub"} }

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Job, error) {
	return []Job{}, nil
}
