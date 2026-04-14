package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// kernelCheck defines a single kernel parameter check.
type kernelCheck struct {
	ID          string
	Path        string
	Title       string
	CWEID       string
	CWEName     string
	Severity    model.Severity
	Remediation string
	CISControl  string
	// IsInsecure returns true when the sysctl value is insecure.
	IsInsecure func(value string) bool
	Expected   string
}

var kernelChecks = []kernelCheck{
	{
		ID:          "kern-001",
		Path:        "/proc/sys/kernel/randomize_va_space",
		Title:       "ASLR disabled",
		CWEID:       "CWE-330",
		CWEName:     "Use of Insufficiently Random Values",
		Severity:    model.SeverityHigh,
		Remediation: "Enable ASLR: sysctl -w kernel.randomize_va_space=2",
		CISControl:  "1.5.2",
		Expected:    "kernel.randomize_va_space = 2",
		IsInsecure:  func(v string) bool { return v == "0" },
	},
	{
		ID:          "kern-002",
		Path:        "/proc/sys/kernel/dmesg_restrict",
		Title:       "Kernel dmesg not restricted",
		CWEID:       "CWE-200",
		CWEName:     "Exposure of Sensitive Information",
		Severity:    model.SeverityMedium,
		Remediation: "Restrict dmesg: sysctl -w kernel.dmesg_restrict=1",
		CISControl:  "1.5.3",
		Expected:    "kernel.dmesg_restrict = 1",
		IsInsecure:  func(v string) bool { return v == "0" },
	},
	{
		ID:          "kern-003",
		Path:        "/proc/sys/kernel/kptr_restrict",
		Title:       "Kernel pointer addresses exposed",
		CWEID:       "CWE-200",
		CWEName:     "Exposure of Sensitive Information",
		Severity:    model.SeverityMedium,
		Remediation: "Restrict kernel pointers: sysctl -w kernel.kptr_restrict=2",
		CISControl:  "1.5.3",
		Expected:    "kernel.kptr_restrict >= 1",
		IsInsecure:  func(v string) bool { return v == "0" },
	},
	{
		ID:          "kern-004",
		Path:        "/proc/sys/net/ipv4/ip_forward",
		Title:       "IP forwarding enabled on non-router",
		CWEID:       "CWE-441",
		CWEName:     "Unintended Proxy or Intermediary",
		Severity:    model.SeverityMedium,
		Remediation: "Disable IP forwarding: sysctl -w net.ipv4.ip_forward=0",
		CISControl:  "3.1.1",
		Expected:    "net.ipv4.ip_forward = 0",
		IsInsecure:  func(v string) bool { return v == "1" },
	},
	{
		ID:          "kern-005",
		Path:        "/proc/sys/net/ipv4/conf/all/accept_redirects",
		Title:       "ICMP redirects accepted",
		CWEID:       "CWE-940",
		CWEName:     "Improper Verification of Source of a Communication Channel",
		Severity:    model.SeverityMedium,
		Remediation: "Disable ICMP redirects: sysctl -w net.ipv4.conf.all.accept_redirects=0",
		CISControl:  "3.2.2",
		Expected:    "net.ipv4.conf.all.accept_redirects = 0",
		IsInsecure:  func(v string) bool { return v == "1" },
	},
	{
		ID:          "kern-006",
		Path:        "/proc/sys/kernel/core_pattern",
		Title:       "Core dump pattern may be writable",
		CWEID:       "CWE-427",
		CWEName:     "Uncontrolled Search Path Element",
		Severity:    model.SeverityLow,
		Remediation: "Set core_pattern to a restricted path or pipe to a controlled handler",
		CISControl:  "1.5.1",
		Expected:    "core_pattern should use a pipe (|) to a controlled handler or be in a restricted directory",
		IsInsecure: func(v string) bool {
			// Insecure if it writes to a world-writable directory (e.g., /tmp)
			return strings.HasPrefix(v, "/tmp/") || strings.HasPrefix(v, "/var/tmp/")
		},
	},
}

// Kernel audits kernel security parameters via /proc/sys.
type Kernel struct{}

// NewKernel creates a Kernel auditor.
func NewKernel() *Kernel { return &Kernel{} }

// Name returns the auditor identifier.
func (k *Kernel) Name() string { return "kernel" }

// Audit reads kernel parameters from /proc/sys and checks for insecure values.
func (k *Kernel) Audit(_ context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	return EvaluateKernelParams(asset), nil
}

// ReadProcSys reads a single sysctl value from /proc/sys. Returns empty
// string on any error (missing file, permission denied, etc.).
func ReadProcSys(path string) string {
	data, err := os.ReadFile(path) //#nosec G304 -- paths are static constants
	if err != nil {
		if os.IsPermission(err) {
			slog.Debug("kernel auditor: permission denied", "path", path)
		}
		return ""
	}
	return strings.TrimSpace(string(data))
}

// EvaluateKernelParams checks all kernel parameters and returns findings.
func EvaluateKernelParams(asset model.Asset) []model.ConfigFinding {
	now := time.Now().UTC()
	var findings []model.ConfigFinding

	for _, check := range kernelChecks {
		value := ReadProcSys(check.Path)
		if value == "" {
			continue // file not readable, skip
		}
		if !check.IsInsecure(value) {
			continue
		}

		findings = append(findings, model.ConfigFinding{
			ID:          uuid.Must(uuid.NewV7()),
			AssetID:     asset.ID,
			Auditor:     "kernel",
			CheckID:     check.ID,
			Title:       check.Title,
			Severity:    check.Severity,
			CWEID:       check.CWEID,
			CWEName:     check.CWEName,
			Evidence:    fmt.Sprintf("%s = %s", check.Path, value),
			Expected:    check.Expected,
			Remediation: check.Remediation,
			CISControl:  check.CISControl,
			Timestamp:   now,
		})
	}

	return findings
}

// Compile-time interface check.
var _ Auditor = (*Kernel)(nil)
