package audit

import (
	"context"
	"fmt"
	"io/fs"
	"testing"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func testAsset() model.Asset {
	return model.Asset{
		ID:       uuid.Must(uuid.NewV7()),
		Hostname: "test-host",
	}
}

// --- SSH auditor tests ---

func TestEvaluateSSHSettings_InsecureRootLogin(t *testing.T) {
	settings := map[string]string{
		"PermitRootLogin": "yes",
	}
	findings := EvaluateSSHSettings(settings, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != "ssh-001" {
		t.Errorf("expected check ssh-001, got %s", findings[0].CheckID)
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected severity high, got %s", findings[0].Severity)
	}
	if findings[0].CWEID != "CWE-250" {
		t.Errorf("expected CWE-250, got %s", findings[0].CWEID)
	}
}

func TestEvaluateSSHSettings_SecureConfig(t *testing.T) {
	settings := map[string]string{
		"PermitRootLogin":      "no",
		"PasswordAuthentication": "no",
		"PermitEmptyPasswords": "no",
		"Protocol":             "2",
		"X11Forwarding":        "no",
		"MaxAuthTries":         "4",
		"AllowTcpForwarding":   "no",
	}
	findings := EvaluateSSHSettings(settings, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for secure config, got %d", len(findings))
	}
}

func TestEvaluateSSHSettings_MultipleInsecure(t *testing.T) {
	settings := map[string]string{
		"PermitRootLogin":    "yes",
		"PermitEmptyPasswords": "yes",
		"Protocol":           "1",
	}
	findings := EvaluateSSHSettings(settings, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.CheckID] = true
	}
	for _, expected := range []string{"ssh-001", "ssh-003", "ssh-004"} {
		if !ids[expected] {
			t.Errorf("expected check %s in findings", expected)
		}
	}
}

func TestEvaluateSSHSettings_MaxAuthTriesBoundary(t *testing.T) {
	// 6 is the threshold - should NOT trigger
	settings := map[string]string{"MaxAuthTries": "6"}
	findings := EvaluateSSHSettings(settings, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 0 {
		t.Fatalf("MaxAuthTries=6 should not trigger, got %d findings", len(findings))
	}

	// 7 should trigger
	settings["MaxAuthTries"] = "7"
	findings = EvaluateSSHSettings(settings, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 1 {
		t.Fatalf("MaxAuthTries=7 should trigger, got %d findings", len(findings))
	}
}

func TestEvaluateSSHSettings_EmptySettings(t *testing.T) {
	findings := EvaluateSSHSettings(map[string]string{}, testAsset(), "/etc/ssh/sshd_config")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty settings, got %d", len(findings))
	}
}

// --- Firewall auditor tests ---

func TestEvaluateFirewall_NoFirewall(t *testing.T) {
	findings := EvaluateFirewall(
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != "fw-001" {
		t.Errorf("expected fw-001, got %s", findings[0].CheckID)
	}
}

func TestEvaluateFirewall_InputAccept(t *testing.T) {
	iptables := `Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0`

	findings := EvaluateFirewall(
		iptables, nil,
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)

	hasInputAccept := false
	for _, f := range findings {
		if f.CheckID == "fw-002" {
			hasInputAccept = true
		}
	}
	if !hasInputAccept {
		t.Error("expected fw-002 (INPUT ACCEPT) finding")
	}
}

func TestEvaluateFirewall_ForwardAccept(t *testing.T) {
	iptables := `Chain INPUT (policy DROP)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0`

	findings := EvaluateFirewall(
		iptables, nil,
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)

	hasForwardAccept := false
	for _, f := range findings {
		if f.CheckID == "fw-003" {
			hasForwardAccept = true
		}
	}
	if !hasForwardAccept {
		t.Error("expected fw-003 (FORWARD ACCEPT) finding")
	}
}

func TestEvaluateFirewall_SSHOpenToAll(t *testing.T) {
	iptables := `Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination`

	findings := EvaluateFirewall(
		iptables, nil,
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)

	hasSSHOpen := false
	for _, f := range findings {
		if f.CheckID == "fw-004" {
			hasSSHOpen = true
		}
	}
	if !hasSSHOpen {
		t.Error("expected fw-004 (SSH open to all) finding")
	}
}

func TestEvaluateFirewall_DBPortOpenToAll(t *testing.T) {
	iptables := `Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:3306
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:5432

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination`

	findings := EvaluateFirewall(
		iptables, nil,
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)

	dbFindings := 0
	for _, f := range findings {
		if f.CheckID == "fw-005" {
			dbFindings++
		}
	}
	if dbFindings != 2 {
		t.Errorf("expected 2 fw-005 findings (MySQL+PostgreSQL), got %d", dbFindings)
	}
}

func TestEvaluateFirewall_SecureConfig(t *testing.T) {
	iptables := `Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  10.0.0.0/8           0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination`

	findings := EvaluateFirewall(
		iptables, nil,
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		testAsset(),
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for secure iptables, got %d", len(findings))
	}
}

func TestEvaluateFirewall_UfwActive(t *testing.T) {
	findings := EvaluateFirewall(
		"", fmt.Errorf("not found"),
		"", fmt.Errorf("not found"),
		"Status: active", nil,
		testAsset(),
	)
	// UFW active means no fw-001
	for _, f := range findings {
		if f.CheckID == "fw-001" {
			t.Error("should not report fw-001 when ufw is active")
		}
	}
}

// --- Kernel auditor tests ---

func TestEvaluateKernelParams(t *testing.T) {
	// This tests the evaluation function directly. Since it reads /proc/sys,
	// we test ReadProcSys separately for non-existent paths.
	value := ReadProcSys("/proc/sys/kernel/nonexistent_param_test_12345")
	if value != "" {
		t.Errorf("expected empty string for nonexistent param, got %q", value)
	}
}

func TestReadProcSys_NonExistent(t *testing.T) {
	v := ReadProcSys("/tmp/nonexistent_kite_test_file")
	if v != "" {
		t.Errorf("expected empty string, got %q", v)
	}
}

// --- Permissions auditor tests ---

// Note: EvaluatePermissions calls os.Stat on real paths. We can't test
// the insecure file detection easily without root, but we can verify
// that it handles non-existent files correctly.

func TestEvaluatePermissions_NonExistentFiles(t *testing.T) {
	checks := []permCheck{
		{
			ID:          "test-001",
			Path:        "/tmp/nonexistent_kite_perm_test",
			Title:       "Test file",
			Severity:    model.SeverityHigh,
			Remediation: "fix it",
			Expected:    "mode 0600",
			IsInsecure:  func(m fs.FileMode) bool { return true },
		},
	}
	findings := EvaluatePermissions(checks, testAsset())
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-existent file, got %d", len(findings))
	}
}

func TestNewPermissions_DeduplicatesAdditionalPaths(t *testing.T) {
	p := NewPermissions([]string{"/etc/shadow", "/custom/path"})
	count := 0
	for _, c := range p.checks {
		if c.Path == "/etc/shadow" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /etc/shadow to appear once, got %d", count)
	}

	hasCustom := false
	for _, c := range p.checks {
		if c.Path == "/custom/path" {
			hasCustom = true
		}
	}
	if !hasCustom {
		t.Error("expected /custom/path to be added")
	}
}

// --- Service auditor tests ---

func TestParseSSOutput(t *testing.T) {
	raw := `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      128          0.0.0.0:3306       0.0.0.0:*
LISTEN 0      128        127.0.0.1:6379       0.0.0.0:*
LISTEN 0      128             [::]:80            [::]:*`

	ports := ParseSSOutput(raw)
	if len(ports) != 4 {
		t.Fatalf("expected 4 ports, got %d", len(ports))
	}

	portMap := make(map[int]string)
	for _, p := range ports {
		portMap[p.Port] = p.Address
	}

	if addr, ok := portMap[22]; !ok || addr != "0.0.0.0" {
		t.Errorf("expected port 22 on 0.0.0.0, got %q", addr)
	}
	if addr, ok := portMap[3306]; !ok || addr != "0.0.0.0" {
		t.Errorf("expected port 3306 on 0.0.0.0, got %q", addr)
	}
	if addr, ok := portMap[6379]; !ok || addr != "127.0.0.1" {
		t.Errorf("expected port 6379 on 127.0.0.1, got %q", addr)
	}
	if addr, ok := portMap[80]; !ok || addr != "::" {
		t.Errorf("expected port 80 on ::, got %q", addr)
	}
}

func TestEvaluateServices_TelnetListening(t *testing.T) {
	ports := []ListeningPort{
		{Port: 23, Address: "127.0.0.1"}, // telnet on localhost still bad
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for telnet, got %d", len(findings))
	}
	if findings[0].CheckID != "svc-001" {
		t.Errorf("expected svc-001, got %s", findings[0].CheckID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestEvaluateServices_RedisOnLocalhost(t *testing.T) {
	ports := []ListeningPort{
		{Port: 6379, Address: "127.0.0.1"},
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for Redis on localhost, got %d", len(findings))
	}
}

func TestEvaluateServices_RedisOnWildcard(t *testing.T) {
	ports := []ListeningPort{
		{Port: 6379, Address: "0.0.0.0"},
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for Redis on 0.0.0.0, got %d", len(findings))
	}
	if findings[0].CheckID != "svc-005" {
		t.Errorf("expected svc-005, got %s", findings[0].CheckID)
	}
}

func TestEvaluateServices_NoInsecurePorts(t *testing.T) {
	ports := []ListeningPort{
		{Port: 443, Address: "0.0.0.0"},
		{Port: 8080, Address: "0.0.0.0"},
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe ports, got %d", len(findings))
	}
}

func TestEvaluateServices_MySQLOnWildcard(t *testing.T) {
	ports := []ListeningPort{
		{Port: 3306, Address: "0.0.0.0"},
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for MySQL on 0.0.0.0, got %d", len(findings))
	}
	if findings[0].CheckID != "svc-004" {
		t.Errorf("expected svc-004, got %s", findings[0].CheckID)
	}
}

func TestEvaluateServices_PostgreSQLOnWildcard(t *testing.T) {
	ports := []ListeningPort{
		{Port: 5432, Address: "::"},
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for PostgreSQL on ::, got %d", len(findings))
	}
}

func TestEvaluateServices_FTPListening(t *testing.T) {
	ports := []ListeningPort{
		{Port: 21, Address: "192.168.1.1"}, // FTP on any address is bad
	}
	findings := EvaluateServices(ports, testAsset())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for FTP, got %d", len(findings))
	}
	if findings[0].CheckID != "svc-002" {
		t.Errorf("expected svc-002, got %s", findings[0].CheckID)
	}
}

func TestParseSSOutput_EmptyInput(t *testing.T) {
	ports := ParseSSOutput("")
	if len(ports) != 0 {
		t.Fatalf("expected 0 ports for empty input, got %d", len(ports))
	}
}

func TestParseSSOutput_WildcardAddress(t *testing.T) {
	raw := `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN 0      128              *:80               *:*`

	ports := ParseSSOutput(raw)
	if len(ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(ports))
	}
	if ports[0].Address != "0.0.0.0" {
		t.Errorf("expected * to be normalized to 0.0.0.0, got %q", ports[0].Address)
	}
}

// --- parseAddrPort tests ---

func TestParseAddrPort(t *testing.T) {
	tests := []struct {
		input    string
		wantAddr string
		wantPort int
	}{
		{"0.0.0.0:22", "0.0.0.0", 22},
		{"127.0.0.1:3306", "127.0.0.1", 3306},
		{"[::]:80", "::", 80},
		{"[::1]:443", "::1", 443},
		{"*:8080", "0.0.0.0", 8080},
		{"invalid", "", 0},
		{"[::invalid", "", 0},
	}

	for _, tt := range tests {
		addr, port := parseAddrPort(tt.input)
		if addr != tt.wantAddr || port != tt.wantPort {
			t.Errorf("parseAddrPort(%q) = (%q, %d), want (%q, %d)",
				tt.input, addr, port, tt.wantAddr, tt.wantPort)
		}
	}
}

// --- Registry tests ---

func TestRegistry_AuditAll_Empty(t *testing.T) {
	reg := NewRegistry()
	findings, err := reg.AuditAll(context.Background(), testAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings from empty registry, got %d", len(findings))
	}
}

// --- Firewall helpers ---

func TestIsIptablesEmpty(t *testing.T) {
	empty := `Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination`

	if !isIptablesEmpty(empty) {
		t.Error("expected empty iptables to return true")
	}

	withRules := `Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination`

	if isIptablesEmpty(withRules) {
		t.Error("expected non-empty iptables to return false")
	}
}

func TestIsNftEmpty(t *testing.T) {
	if !isNftEmpty("") {
		t.Error("expected empty string to be empty nft")
	}
	if !isNftEmpty("table") {
		t.Error("expected 'table' to be empty nft")
	}
	if isNftEmpty("table inet filter {\n  chain input {\n  }\n}") {
		t.Error("expected ruleset with chain to not be empty")
	}
}

func TestPortOpenToAll(t *testing.T) {
	output := `Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
ACCEPT     tcp  --  10.0.0.0/8           0.0.0.0/0            tcp dpt:3306`

	if !portOpenToAll(output, "22") {
		t.Error("expected port 22 to be open to all")
	}
	if portOpenToAll(output, "3306") {
		t.Error("expected port 3306 to NOT be open to all (source restricted)")
	}
	if portOpenToAll(output, "443") {
		t.Error("expected port 443 to NOT be open to all (not in rules)")
	}
}
