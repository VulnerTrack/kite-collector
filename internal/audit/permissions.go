package audit

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// permCheck defines a single file permission check.
type permCheck struct {
	ID          string
	Path        string
	Title       string
	Severity    model.Severity
	Remediation string
	CISControl  string
	// IsInsecure returns true when the file mode is insecure.
	IsInsecure func(mode fs.FileMode) bool
	// Expected describes the secure permission.
	Expected string
}

var defaultPermChecks = []permCheck{
	{
		ID:          "perm-001",
		Path:        "/etc/shadow",
		Title:       "/etc/shadow is world-readable",
		Severity:    model.SeverityCritical,
		Remediation: "chmod 640 /etc/shadow",
		CISControl:  "6.1.3",
		Expected:    "Mode 0640 or more restrictive (no world or group read beyond shadow group)",
		IsInsecure: func(m fs.FileMode) bool {
			// World-readable: others have read (0o004) or group-readable beyond expected
			return m.Perm()&0o044 != 0
		},
	},
	{
		ID:          "perm-002",
		Path:        "/etc/passwd",
		Title:       "/etc/passwd is world-writable",
		Severity:    model.SeverityCritical,
		Remediation: "chmod 644 /etc/passwd",
		CISControl:  "6.1.2",
		Expected:    "Mode 0644 or more restrictive (not world-writable)",
		IsInsecure: func(m fs.FileMode) bool {
			return m.Perm()&0o002 != 0
		},
	},
	{
		ID:          "perm-003",
		Path:        "/etc/sudoers",
		Title:       "/etc/sudoers has excessive permissions",
		Severity:    model.SeverityHigh,
		Remediation: "chmod 440 /etc/sudoers",
		CISControl:  "6.1.4",
		Expected:    "Mode 0440 or more restrictive",
		IsInsecure: func(m fs.FileMode) bool {
			// World-readable or writable
			return m.Perm()&0o006 != 0
		},
	},
	{
		ID:          "perm-004",
		Path:        "/etc/crontab",
		Title:       "/etc/crontab is world-writable",
		Severity:    model.SeverityHigh,
		Remediation: "chmod 600 /etc/crontab",
		CISControl:  "5.1.2",
		Expected:    "Mode 0600 or more restrictive (not world-writable)",
		IsInsecure: func(m fs.FileMode) bool {
			return m.Perm()&0o002 != 0
		},
	},
	{
		ID:          "perm-005",
		Path:        "/root/.ssh/authorized_keys",
		Title:       "Root authorized_keys is world-readable",
		Severity:    model.SeverityHigh,
		Remediation: "chmod 600 /root/.ssh/authorized_keys",
		CISControl:  "5.2.17",
		Expected:    "Mode 0600 (owner read-write only)",
		IsInsecure: func(m fs.FileMode) bool {
			return m.Perm()&0o044 != 0
		},
	},
	{
		ID:          "perm-006",
		Path:        "/etc/ssh/sshd_config",
		Title:       "sshd_config is world-writable",
		Severity:    model.SeverityCritical,
		Remediation: "chmod 600 /etc/ssh/sshd_config",
		CISControl:  "5.2.1",
		Expected:    "Mode 0600 or more restrictive (not world-writable)",
		IsInsecure: func(m fs.FileMode) bool {
			return m.Perm()&0o002 != 0
		},
	},
}

// Permissions audits critical file permissions using os.Stat().
type Permissions struct {
	checks []permCheck
}

// NewPermissions creates a Permissions auditor. If additionalPaths is provided,
// they are checked for world-writable permissions in addition to the defaults.
func NewPermissions(additionalPaths []string) *Permissions {
	checks := make([]permCheck, len(defaultPermChecks))
	copy(checks, defaultPermChecks)

	// Add extra paths as world-writable checks.
	for i, p := range additionalPaths {
		alreadyExists := false
		for _, c := range checks {
			if c.Path == p {
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}
		checks = append(checks, permCheck{
			ID:          fmt.Sprintf("perm-extra-%d", i+1),
			Path:        p,
			Title:       fmt.Sprintf("%s has excessive permissions", p),
			Severity:    model.SeverityMedium,
			Remediation: fmt.Sprintf("Review and restrict permissions on %s", p),
			CISControl:  "",
			Expected:    "Not world-writable",
			IsInsecure: func(m fs.FileMode) bool {
				return m.Perm()&0o002 != 0
			},
		})
	}

	return &Permissions{checks: checks}
}

// Name returns the auditor identifier.
func (p *Permissions) Name() string { return "permissions" }

// Audit checks file permissions on critical system files.
func (p *Permissions) Audit(_ context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	return EvaluatePermissions(p.checks, asset), nil
}

// EvaluatePermissions checks file modes against expected permissions.
func EvaluatePermissions(checks []permCheck, asset model.Asset) []model.ConfigFinding {
	now := time.Now().UTC()
	var findings []model.ConfigFinding

	for _, check := range checks {
		info, err := os.Stat(check.Path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				slog.Debug("permissions auditor: stat denied", "path", check.Path)
				continue
			}
			slog.Warn("permissions auditor: stat failed", "path", check.Path, "error", err)
			continue
		}

		mode := info.Mode()
		if !check.IsInsecure(mode) {
			continue
		}

		findings = append(findings, model.ConfigFinding{
			ID:          uuid.Must(uuid.NewV7()),
			AssetID:     asset.ID,
			Auditor:     "permissions",
			CheckID:     check.ID,
			Title:       check.Title,
			Severity:    check.Severity,
			CWEID:       "CWE-732",
			CWEName:     "Incorrect Permission Assignment for Critical Resource",
			Evidence:    fmt.Sprintf("%s mode=%04o", check.Path, mode.Perm()),
			Expected:    check.Expected,
			Remediation: check.Remediation,
			CISControl:  check.CISControl,
			Timestamp:   now,
		})
	}

	return findings
}

// Compile-time interface check.
var _ Auditor = (*Permissions)(nil)
