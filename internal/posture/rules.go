package posture

import "github.com/vulnertrack/kite-collector/internal/model"

// Rule maps a set of CWE findings to a CAPEC attack pattern.
// All RequiredCWEs must be present in the asset's findings for the rule
// to match.
type Rule struct {
	CAPECID    string
	CAPECName  string
	Likelihood model.Severity // reuse severity enum for likelihood
	Mitigation string
	RequiredCWEs []string // ALL must be present
}

// Rules defines the static CWE→CAPEC mapping table. Each rule represents
// a known attack pattern that becomes feasible when specific configuration
// weaknesses are present.
var Rules = []Rule{
	{
		CAPECID:      "CAPEC-49",
		CAPECName:    "Password Brute Forcing",
		RequiredCWEs: []string{"CWE-287"},
		Likelihood:   model.SeverityHigh,
		Mitigation:   "Disable PasswordAuthentication in sshd_config. Use key-based auth only.",
	},
	{
		CAPECID:      "CAPEC-70",
		CAPECName:    "Try Common Credentials",
		RequiredCWEs: []string{"CWE-258"},
		Likelihood:   model.SeverityCritical,
		Mitigation:   "Disable PermitEmptyPasswords in sshd_config. Enforce strong password policies.",
	},
	{
		CAPECID:      "CAPEC-115",
		CAPECName:    "Authentication Bypass",
		RequiredCWEs: []string{"CWE-250"},
		Likelihood:   model.SeverityHigh,
		Mitigation:   "Disable root login via SSH. Use sudo for privilege escalation.",
	},
	{
		CAPECID:      "CAPEC-125",
		CAPECName:    "Flooding",
		RequiredCWEs: []string{"CWE-284", "CWE-770"},
		Likelihood:   model.SeverityMedium,
		Mitigation:   "Enable firewall with default-deny policy. Add rate limiting for exposed services.",
	},
	{
		CAPECID:      "CAPEC-169",
		CAPECName:    "Footprinting",
		RequiredCWEs: []string{"CWE-200"},
		Likelihood:   model.SeverityMedium,
		Mitigation:   "Restrict kernel information exposure: dmesg_restrict=1 and kptr_restrict>=1.",
	},
	{
		CAPECID:      "CAPEC-220",
		CAPECName:    "Client-Server Protocol Manipulation",
		RequiredCWEs: []string{"CWE-319"},
		Likelihood:   model.SeverityHigh,
		Mitigation:   "Disable cleartext protocols (telnet, FTP). Use encrypted alternatives (SSH, SFTP).",
	},
	{
		CAPECID:      "CAPEC-560",
		CAPECName:    "Use of Known Domain Credentials",
		RequiredCWEs: []string{"CWE-284"},
		Likelihood:   model.SeverityHigh,
		Mitigation:   "Restrict database and cache services to localhost. Use firewall rules to block external access.",
	},
	{
		CAPECID:      "CAPEC-122",
		CAPECName:    "Privilege Abuse",
		RequiredCWEs: []string{"CWE-732"},
		Likelihood:   model.SeverityHigh,
		Mitigation:   "Correct file permissions on critical system files (/etc/shadow, /etc/sudoers, sshd_config).",
	},
	{
		CAPECID:      "CAPEC-233",
		CAPECName:    "Privilege Escalation",
		RequiredCWEs: []string{"CWE-250", "CWE-732"},
		Likelihood:   model.SeverityCritical,
		Mitigation:   "Disable root SSH login and fix file permissions to prevent privilege escalation chains.",
	},
	{
		CAPECID:      "CAPEC-216",
		CAPECName:    "Communication Channel Manipulation",
		RequiredCWEs: []string{"CWE-441"},
		Likelihood:   model.SeverityMedium,
		Mitigation:   "Disable IP forwarding and SSH TCP forwarding unless explicitly required.",
	},
	{
		CAPECID:      "CAPEC-112",
		CAPECName:    "Brute Force",
		RequiredCWEs: []string{"CWE-307"},
		Likelihood:   model.SeverityMedium,
		Mitigation:   "Set MaxAuthTries to 4 or lower in sshd_config. Enable fail2ban.",
	},
	{
		CAPECID:      "CAPEC-66",
		CAPECName:    "SQL Injection",
		RequiredCWEs: []string{"CWE-284", "CWE-319"},
		Likelihood:   model.SeverityCritical,
		Mitigation:   "Bind databases to localhost and disable cleartext protocols to prevent credential interception.",
	},
}
