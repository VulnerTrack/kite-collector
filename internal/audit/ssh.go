package audit

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// sshCheck defines a single SSH configuration check.
type sshCheck struct {
	ID          string
	Setting     string
	Title       string
	CWEID       string
	CWEName     string
	Severity    model.Severity
	Remediation string
	CISControl  string
	// IsInsecure returns true when the setting value is insecure.
	IsInsecure func(value string) bool
	// Expected describes the secure value.
	Expected string
}

var sshChecks = []sshCheck{
	{
		ID:          "ssh-001",
		Setting:     "PermitRootLogin",
		Title:       "SSH permits root login",
		CWEID:       "CWE-250",
		CWEName:     "Execution with Unnecessary Privileges",
		Severity:    model.SeverityHigh,
		Remediation: "Set PermitRootLogin to no in sshd_config",
		CISControl:  "5.2.10",
		IsInsecure:  func(v string) bool { return strings.EqualFold(v, "yes") },
		Expected:    "PermitRootLogin no",
	},
	{
		ID:          "ssh-002",
		Setting:     "PasswordAuthentication",
		Title:       "SSH allows password authentication",
		CWEID:       "CWE-287",
		CWEName:     "Improper Authentication",
		Severity:    model.SeverityMedium,
		Remediation: "Set PasswordAuthentication to no. Use key-based auth only.",
		CISControl:  "5.2.8",
		IsInsecure:  func(v string) bool { return strings.EqualFold(v, "yes") },
		Expected:    "PasswordAuthentication no",
	},
	{
		ID:          "ssh-003",
		Setting:     "PermitEmptyPasswords",
		Title:       "SSH permits empty passwords",
		CWEID:       "CWE-258",
		CWEName:     "Empty Password in Configuration File",
		Severity:    model.SeverityCritical,
		Remediation: "Set PermitEmptyPasswords to no in sshd_config",
		CISControl:  "5.2.9",
		IsInsecure:  func(v string) bool { return strings.EqualFold(v, "yes") },
		Expected:    "PermitEmptyPasswords no",
	},
	{
		ID:          "ssh-004",
		Setting:     "Protocol",
		Title:       "SSH uses insecure protocol version 1",
		CWEID:       "CWE-327",
		CWEName:     "Use of a Broken or Risky Cryptographic Algorithm",
		Severity:    model.SeverityCritical,
		Remediation: "Set Protocol to 2 in sshd_config",
		CISControl:  "5.2.4",
		IsInsecure:  func(v string) bool { return v == "1" },
		Expected:    "Protocol 2",
	},
	{
		ID:          "ssh-005",
		Setting:     "X11Forwarding",
		Title:       "SSH X11 forwarding enabled",
		CWEID:       "CWE-829",
		CWEName:     "Inclusion of Functionality from Untrusted Control Sphere",
		Severity:    model.SeverityLow,
		Remediation: "Set X11Forwarding to no unless required",
		CISControl:  "5.2.6",
		IsInsecure:  func(v string) bool { return strings.EqualFold(v, "yes") },
		Expected:    "X11Forwarding no",
	},
	{
		ID:          "ssh-006",
		Setting:     "MaxAuthTries",
		Title:       "SSH MaxAuthTries too high",
		CWEID:       "CWE-307",
		CWEName:     "Improper Restriction of Excessive Authentication Attempts",
		Severity:    model.SeverityMedium,
		Remediation: "Set MaxAuthTries to 4 or lower",
		CISControl:  "5.2.5",
		IsInsecure: func(v string) bool {
			n, err := strconv.Atoi(v)
			return err == nil && n > 6
		},
		Expected: "MaxAuthTries <= 6",
	},
	{
		ID:          "ssh-007",
		Setting:     "AllowTcpForwarding",
		Title:       "SSH TCP forwarding enabled",
		CWEID:       "CWE-441",
		CWEName:     "Unintended Proxy or Intermediary",
		Severity:    model.SeverityMedium,
		Remediation: "Set AllowTcpForwarding to no on bastion/jump hosts",
		CISControl:  "5.2.20",
		IsInsecure:  func(v string) bool { return strings.EqualFold(v, "yes") },
		Expected:    "AllowTcpForwarding no",
	},
}

// SSH audits the OpenSSH server configuration.
type SSH struct {
	configPath string
}

// NewSSH creates an SSH auditor. If configPath is empty it defaults to
// /etc/ssh/sshd_config.
func NewSSH(configPath string) *SSH {
	if configPath == "" {
		configPath = "/etc/ssh/sshd_config"
	}
	return &SSH{configPath: configPath}
}

// Name returns the auditor identifier.
func (s *SSH) Name() string { return "ssh" }

// Audit parses sshd_config and checks settings against known-insecure values.
func (s *SSH) Audit(_ context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	settings, err := ParseSSHDConfig(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("ssh auditor: config not found, skipping", "path", s.configPath)
			return nil, nil
		}
		if os.IsPermission(err) {
			slog.Warn("ssh auditor: permission denied, skipping", "path", s.configPath)
			return nil, nil
		}
		return nil, fmt.Errorf("ssh audit: %w", err)
	}

	return EvaluateSSHSettings(settings, asset, s.configPath), nil
}

// ParseSSHDConfig reads an sshd_config file and returns key-value settings.
// Comment lines and empty lines are skipped. Keys are case-insensitive.
func ParseSSHDConfig(path string) (map[string]string, error) {
	f, err := os.Open(path) //#nosec G304 -- path from trusted config
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	settings := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// sshd_config uses "Key Value" format (space or tab separated).
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// First occurrence wins in sshd_config.
		key := parts[0]
		if _, exists := settings[key]; !exists {
			settings[key] = parts[1]
		}
	}

	return settings, scanner.Err()
}

// EvaluateSSHSettings checks parsed sshd_config settings against known
// insecure values and returns findings.
func EvaluateSSHSettings(settings map[string]string, asset model.Asset, configPath string) []model.ConfigFinding {
	now := time.Now().UTC()
	var findings []model.ConfigFinding

	for _, check := range sshChecks {
		value, exists := settings[check.Setting]
		if !exists {
			continue
		}
		if !check.IsInsecure(value) {
			continue
		}

		findings = append(findings, model.ConfigFinding{
			ID:          uuid.Must(uuid.NewV7()),
			AssetID:     asset.ID,
			Auditor:     "ssh",
			CheckID:     check.ID,
			Title:       check.Title,
			Severity:    check.Severity,
			CWEID:       check.CWEID,
			CWEName:     check.CWEName,
			Evidence:    fmt.Sprintf("%s %s in %s", check.Setting, value, configPath),
			Expected:    check.Expected,
			Remediation: check.Remediation,
			CISControl:  check.CISControl,
			Timestamp:   now,
		})
	}

	return findings
}

// Compile-time interface check.
var _ Auditor = (*SSH)(nil)
