package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Firewall audits the system firewall configuration by checking iptables,
// nftables, and ufw.
type Firewall struct{}

// NewFirewall creates a Firewall auditor.
func NewFirewall() *Firewall { return &Firewall{} }

// Name returns the auditor identifier.
func (f *Firewall) Name() string { return "firewall" }

// Audit checks firewall status and rule configuration.
func (f *Firewall) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	iptablesOut, iptablesErr := runCmd(ctx, "iptables", "-L", "-n")
	nftOut, nftErr := runCmd(ctx, "nft", "list", "ruleset")
	ufwOut, ufwErr := runCmd(ctx, "ufw", "status")

	return EvaluateFirewall(iptablesOut, iptablesErr, nftOut, nftErr, ufwOut, ufwErr, asset), nil
}

// EvaluateFirewall analyzes firewall command outputs and produces findings.
func EvaluateFirewall(
	iptablesOut string, iptablesErr error,
	nftOut string, nftErr error,
	ufwOut string, ufwErr error,
	asset model.Asset,
) []model.ConfigFinding {
	now := time.Now().UTC()
	var findings []model.ConfigFinding

	hasIptables := iptablesErr == nil && len(iptablesOut) > 0
	hasNft := nftErr == nil && len(nftOut) > 0
	hasUfw := ufwErr == nil && strings.Contains(ufwOut, "active")

	iptablesEmpty := !hasIptables || isIptablesEmpty(iptablesOut)
	nftEmpty := !hasNft || isNftEmpty(nftOut)

	// fw-001: No firewall active
	if iptablesEmpty && nftEmpty && !hasUfw {
		findings = append(findings, model.ConfigFinding{
			ID:          uuid.Must(uuid.NewV7()),
			AssetID:     asset.ID,
			Auditor:     "firewall",
			CheckID:     "fw-001",
			Title:       "No firewall active",
			Severity:    model.SeverityHigh,
			CWEID:       "CWE-284",
			CWEName:     "Improper Access Control",
			Evidence:    "No active iptables rules, nftables ruleset, or ufw detected",
			Expected:    "At least one firewall should be active with a default-deny policy",
			Remediation: "Enable and configure iptables, nftables, or ufw with a default-deny INPUT policy",
			CISControl:  "3.4.1",
			Timestamp:   now,
		})
		return findings
	}

	// fw-002: Default INPUT policy is ACCEPT
	if hasIptables && !iptablesEmpty {
		if defaultInputAccept(iptablesOut) {
			findings = append(findings, model.ConfigFinding{
				ID:          uuid.Must(uuid.NewV7()),
				AssetID:     asset.ID,
				Auditor:     "firewall",
				CheckID:     "fw-002",
				Title:       "Default INPUT policy is ACCEPT",
				Severity:    model.SeverityHigh,
				CWEID:       "CWE-284",
				CWEName:     "Improper Access Control",
				Evidence:    "iptables INPUT chain default policy is ACCEPT",
				Expected:    "Default INPUT policy should be DROP or REJECT",
				Remediation: "Set default INPUT policy: iptables -P INPUT DROP",
				CISControl:  "3.4.2",
				Timestamp:   now,
			})
		}

		// fw-003: Default FORWARD policy is ACCEPT
		if defaultForwardAccept(iptablesOut) {
			findings = append(findings, model.ConfigFinding{
				ID:          uuid.Must(uuid.NewV7()),
				AssetID:     asset.ID,
				Auditor:     "firewall",
				CheckID:     "fw-003",
				Title:       "Default FORWARD policy is ACCEPT",
				Severity:    model.SeverityMedium,
				CWEID:       "CWE-284",
				CWEName:     "Improper Access Control",
				Evidence:    "iptables FORWARD chain default policy is ACCEPT",
				Expected:    "Default FORWARD policy should be DROP",
				Remediation: "Set default FORWARD policy: iptables -P FORWARD DROP",
				CISControl:  "3.4.2",
				Timestamp:   now,
			})
		}

		// fw-004: SSH open to 0.0.0.0/0 without rate limiting
		if portOpenToAll(iptablesOut, "22") {
			findings = append(findings, model.ConfigFinding{
				ID:          uuid.Must(uuid.NewV7()),
				AssetID:     asset.ID,
				Auditor:     "firewall",
				CheckID:     "fw-004",
				Title:       "SSH (port 22) open to all without rate limiting",
				Severity:    model.SeverityMedium,
				CWEID:       "CWE-770",
				CWEName:     "Allocation of Resources Without Limits or Throttling",
				Evidence:    "Port 22 ACCEPT rule with no source restriction or rate limit in iptables",
				Expected:    "SSH access should be restricted by source IP or rate limited",
				Remediation: "Restrict SSH access to known IPs or add rate limiting rules",
				CISControl:  "3.4.3",
				Timestamp:   now,
			})
		}

		// fw-005: Database ports open to 0.0.0.0/0
		for _, port := range []string{"3306", "5432"} {
			if portOpenToAll(iptablesOut, port) {
				findings = append(findings, model.ConfigFinding{
					ID:          uuid.Must(uuid.NewV7()),
					AssetID:     asset.ID,
					Auditor:     "firewall",
					CheckID:     "fw-005",
					Title:       fmt.Sprintf("Database port %s open to all", port),
					Severity:    model.SeverityCritical,
					CWEID:       "CWE-284",
					CWEName:     "Improper Access Control",
					Evidence:    fmt.Sprintf("Port %s ACCEPT rule with no source restriction in iptables", port),
					Expected:    "Database ports should not be exposed to 0.0.0.0/0",
					Remediation: fmt.Sprintf("Restrict port %s access to application servers only", port),
					CISControl:  "3.4.3",
					Timestamp:   now,
				})
			}
		}
	}

	return findings
}

// isIptablesEmpty returns true when iptables output has only empty chains.
func isIptablesEmpty(output string) bool {
	lines := strings.Split(output, "\n")
	ruleCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "target") {
			continue
		}
		ruleCount++
	}
	return ruleCount == 0
}

// isNftEmpty returns true when nftables has no rules.
func isNftEmpty(output string) bool {
	trimmed := strings.TrimSpace(output)
	return trimmed == "" || trimmed == "table" || !strings.Contains(output, "chain")
}

// defaultInputAccept checks if iptables INPUT chain has a default ACCEPT policy.
func defaultInputAccept(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Chain INPUT") && strings.Contains(line, "policy ACCEPT") {
			return true
		}
	}
	return false
}

// defaultForwardAccept checks if iptables FORWARD chain has a default ACCEPT policy.
func defaultForwardAccept(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Chain FORWARD") && strings.Contains(line, "policy ACCEPT") {
			return true
		}
	}
	return false
}

// portOpenToAll checks if a port has an ACCEPT rule with 0.0.0.0/0 as the
// source address (field index 3 in iptables -L -n output).
func portOpenToAll(output string, port string) bool {
	dptMark := "dpt:" + port
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "ACCEPT") || !strings.Contains(line, dptMark) {
			continue
		}
		fields := strings.Fields(line)
		// iptables -L -n format: target prot opt source destination [match...]
		if len(fields) >= 4 && fields[3] == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

// runCmd executes a command and returns stdout. Errors from missing
// binaries or permission denied are returned as err, not panics.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- args are static
	out, err := cmd.Output()
	if err != nil {
		slog.Debug("audit: command failed", "cmd", name, "error", err)
		return "", fmt.Errorf("run %s: %w", name, err)
	}
	return string(out), nil
}

// Compile-time interface check.
var _ Auditor = (*Firewall)(nil)
