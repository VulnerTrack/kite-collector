package dashboard

import "strings"

// installErrorCategory classifies an install failure into a recovery class
// the UI can surface typed remediations for. The categories deliberately
// stay coarse — UX value comes from collapsing the common failure modes
// into a single action button, not from a thousand bespoke micro-cases.
type installErrorCategory string

const (
	// installErrOther is the empty default — used both as the zero value
	// and the explicit "we don't recognise this error" fallback. The
	// template falls through to the generic CLI hint pre-block.
	installErrOther installErrorCategory = ""

	// installErrPermission means the install lacked OS privileges
	// (non-root unix, non-Administrator Windows). The UI surfaces a
	// one-click "Retry in --user mode" button that re-POSTs install with
	// {user_mode: true}; the server reapplies smart defaults for the
	// user-mode paths so the operator doesn't need to recompute them.
	installErrPermission installErrorCategory = "permission"

	// installErrServiceMgr means the OS service manager isn't reachable
	// (no systemd, no launchd, no SCM). Binary copy may have succeeded;
	// the service registration step failed. The UI suggests running the
	// CLI command with --skip-service (when implemented) or accepting
	// the binary-only install.
	installErrServiceMgr installErrorCategory = "service_manager"

	// installErrDiskWrite means the install path is read-only or out of
	// space. The UI suggests choosing a different --binary-dir.
	installErrDiskWrite installErrorCategory = "disk_write"
)

// categorizeInstallError classifies an install-time error so the UI can
// offer typed recovery actions. Pattern matches are conservative — novel
// errors fall through to installErrOther, which renders the generic CLI
// hint. The match strings are lower-cased on both sides so platform-
// specific capitalization ("Access is denied." on Windows, "permission
// denied" on unix) all land in the same bucket.
//
// Adding a new category: extend the const list, add the regex/contains
// checks here, and add a {{if eq .ErrorCategory "<new>"}} branch in the
// install-status template. Keep this in one place so the taxonomy stays
// auditable.
func categorizeInstallError(err error) installErrorCategory {
	if err == nil {
		return installErrOther
	}
	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "access is denied"),
		strings.Contains(msg, "must be root"),
		strings.Contains(msg, "elevated privileges"):
		return installErrPermission

	case strings.Contains(msg, "no init system"),
		strings.Contains(msg, "service not supported"),
		strings.Contains(msg, "service control manager"):
		return installErrServiceMgr

	case strings.Contains(msg, "systemd") && strings.Contains(msg, "no such file"):
		return installErrServiceMgr

	case strings.Contains(msg, "read-only file system"),
		strings.Contains(msg, "no space left on device"):
		return installErrDiskWrite
	}

	return installErrOther
}
