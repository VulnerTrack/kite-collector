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

// serviceCheck defines a check for a specific listening service.
type serviceCheck struct {
	ID          string
	ServiceName string
	Title       string
	CWEID       string
	CWEName     string
	Severity    model.Severity
	Remediation string
	CISControl  string
	Port        int
}

var defaultServiceChecks = []serviceCheck{
	{
		ID:          "svc-001",
		Port:        23,
		ServiceName: "telnet",
		Title:       "Telnet service listening",
		CWEID:       "CWE-319",
		CWEName:     "Cleartext Transmission of Sensitive Information",
		Severity:    model.SeverityCritical,
		Remediation: "Disable telnet. Use SSH instead.",
		CISControl:  "2.2.19",
	},
	{
		ID:          "svc-002",
		Port:        21,
		ServiceName: "FTP",
		Title:       "FTP service listening",
		CWEID:       "CWE-319",
		CWEName:     "Cleartext Transmission of Sensitive Information",
		Severity:    model.SeverityHigh,
		Remediation: "Disable FTP. Use SFTP or SCP instead.",
		CISControl:  "2.2.16",
	},
	{
		ID:          "svc-003",
		Port:        111,
		ServiceName: "rpcbind",
		Title:       "rpcbind listening on 0.0.0.0",
		CWEID:       "CWE-284",
		CWEName:     "Improper Access Control",
		Severity:    model.SeverityMedium,
		Remediation: "Disable rpcbind or restrict to localhost",
		CISControl:  "2.2.17",
	},
	{
		ID:          "svc-004",
		Port:        3306,
		ServiceName: "MySQL",
		Title:       "MySQL listening on 0.0.0.0",
		CWEID:       "CWE-284",
		CWEName:     "Improper Access Control",
		Severity:    model.SeverityHigh,
		Remediation: "Bind MySQL to 127.0.0.1 or restrict via firewall",
		CISControl:  "",
	},
	{
		ID:          "svc-005",
		Port:        6379,
		ServiceName: "Redis",
		Title:       "Redis listening on 0.0.0.0",
		CWEID:       "CWE-284",
		CWEName:     "Improper Access Control",
		Severity:    model.SeverityCritical,
		Remediation: "Bind Redis to 127.0.0.1 and enable authentication",
		CISControl:  "",
	},
	{
		ID:          "svc-006",
		Port:        9200,
		ServiceName: "Elasticsearch",
		Title:       "Elasticsearch listening on 0.0.0.0",
		CWEID:       "CWE-284",
		CWEName:     "Improper Access Control",
		Severity:    model.SeverityHigh,
		Remediation: "Bind Elasticsearch to 127.0.0.1 or restrict via firewall",
		CISControl:  "",
	},
}

// Additional check for PostgreSQL (port 5432) matching svc-004 pattern.
var postgresCheck = serviceCheck{
	ID:          "svc-004",
	Port:        5432,
	ServiceName: "PostgreSQL",
	Title:       "PostgreSQL listening on 0.0.0.0",
	CWEID:       "CWE-284",
	CWEName:     "Improper Access Control",
	Severity:    model.SeverityHigh,
	Remediation: "Bind PostgreSQL to 127.0.0.1 or restrict via firewall",
	CISControl:  "",
}

// ListeningPort represents a port found by parsing ss or /proc/net/tcp.
type ListeningPort struct {
	Address string // e.g., "0.0.0.0", "127.0.0.1", "::"
	Port    int
}

// Service audits listening network services.
type Service struct {
	criticalPorts []int
}

// NewService creates a Service auditor. If criticalPorts is nil, defaults
// are used.
func NewService(criticalPorts []int) *Service {
	if len(criticalPorts) == 0 {
		criticalPorts = []int{23, 21, 111, 3306, 5432, 6379, 9200}
	}
	return &Service{criticalPorts: criticalPorts}
}

// Name returns the auditor identifier.
func (s *Service) Name() string { return "service" }

// Audit enumerates listening ports and checks for insecure services.
func (s *Service) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	ports, err := discoverListeningPorts(ctx)
	if err != nil {
		slog.Warn("service auditor: failed to discover ports", "error", err)
		return nil, nil
	}

	return EvaluateServices(ports, asset), nil
}

// discoverListeningPorts attempts to parse ss output first, falling back
// to /proc/net/tcp.
func discoverListeningPorts(ctx context.Context) ([]ListeningPort, error) {
	// Try ss first.
	out, err := runCmd(ctx, "ss", "-tlnp")
	if err == nil && out != "" {
		return ParseSSOutput(out), nil
	}

	// Fallback to /proc/net/tcp.
	return parseProcNetTCP()
}

// ParseSSOutput parses the output of ss -tlnp.
func ParseSSOutput(raw string) []ListeningPort {
	var ports []ListeningPort
	scanner := bufio.NewScanner(strings.NewReader(raw))

	for scanner.Scan() {
		line := scanner.Text()
		// Skip header.
		if strings.HasPrefix(line, "State") || !strings.HasPrefix(line, "LISTEN") {
			if !strings.Contains(line, "LISTEN") {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Local address is typically field 3 (0-indexed).
		localAddr := fields[3]
		addr, port := parseAddrPort(localAddr)
		if port > 0 {
			ports = append(ports, ListeningPort{Port: port, Address: addr})
		}
	}

	return ports
}

// parseAddrPort splits "addr:port" or "[::]:port" into address and port.
func parseAddrPort(s string) (string, int) {
	// Handle IPv6 [::]:port
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx < 0 {
			return "", 0
		}
		addr := s[1:idx]
		p, err := strconv.Atoi(s[idx+2:])
		if err != nil {
			return "", 0
		}
		return addr, p
	}

	// Handle IPv4 addr:port or *:port
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0
	}
	addr := s[:idx]
	p, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0
	}
	if addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, p
}

// parseProcNetTCP reads /proc/net/tcp for listening sockets.
func parseProcNetTCP() ([]ListeningPort, error) {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/tcp: %w", err)
	}

	var ports []ListeningPort
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "sl") {
			continue // header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// State 0A = LISTEN
		if fields[3] != "0A" {
			continue
		}

		// local_address is field[1] as hex "ADDR:PORT"
		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}

		port64, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}

		addr := "0.0.0.0"
		if parts[0] != "00000000" {
			addr = "127.0.0.1" // simplified
		}

		ports = append(ports, ListeningPort{Port: int(port64), Address: addr})
	}

	return ports, nil
}

// EvaluateServices checks listening ports against known insecure services.
func EvaluateServices(ports []ListeningPort, asset model.Asset) []model.ConfigFinding {
	now := time.Now().UTC()
	var findings []model.ConfigFinding

	// Build a lookup of all listening ports.
	portMap := make(map[int][]string) // port -> addresses
	for _, p := range ports {
		portMap[p.Port] = append(portMap[p.Port], p.Address)
	}

	allChecks := append(defaultServiceChecks, postgresCheck)

	for _, check := range allChecks {
		addrs, ok := portMap[check.Port]
		if !ok {
			continue
		}

		// For some checks (telnet, FTP) any listening is bad.
		// For others (database, Redis) only 0.0.0.0 or :: is bad.
		isBound := false
		for _, addr := range addrs {
			if check.Port == 23 || check.Port == 21 {
				isBound = true
				break
			}
			if addr == "0.0.0.0" || addr == "::" || addr == "*" {
				isBound = true
				break
			}
		}

		if !isBound {
			continue
		}

		evidence := fmt.Sprintf("%s (port %d) listening on %s",
			check.ServiceName, check.Port, strings.Join(addrs, ", "))

		findings = append(findings, model.ConfigFinding{
			ID:          uuid.Must(uuid.NewV7()),
			AssetID:     asset.ID,
			Auditor:     "service",
			CheckID:     check.ID,
			Title:       check.Title,
			Severity:    check.Severity,
			CWEID:       check.CWEID,
			CWEName:     check.CWEName,
			Evidence:    evidence,
			Expected:    "Service should not be listening or should be bound to 127.0.0.1",
			Remediation: check.Remediation,
			CISControl:  check.CISControl,
			Timestamp:   now,
		})
	}

	return findings
}

// Compile-time interface check.
var _ Auditor = (*Service)(nil)
