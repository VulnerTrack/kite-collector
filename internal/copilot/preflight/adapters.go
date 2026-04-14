package preflight

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DockerSocketChecker probes the Docker socket for connectivity.
type DockerSocketChecker struct{}

func (c *DockerSocketChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	enabled, ok := value.(bool)
	if !ok || !enabled {
		return CheckResult{NodeID: nodeID, Check: "docker:socket:probe", Passed: true, Message: "docker disabled, skipping"}
	}
	sock := "/var/run/docker.sock"
	_, err := os.Stat(sock)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "docker:socket:probe",
			Passed:  false,
			Message: fmt.Sprintf("Docker socket not found at %s", sock),
			Hint:    "Install Docker or set discovery.docker.host to a custom socket path",
		}
	}
	return CheckResult{NodeID: nodeID, Check: "docker:socket:probe", Passed: true, Message: fmt.Sprintf("%s accessible", sock)}
}

// CIDRChecker validates that CIDR scopes parse correctly.
type CIDRChecker struct{}

func (c *CIDRChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	scope, ok := value.(string)
	if !ok || scope == "" {
		return CheckResult{NodeID: nodeID, Check: "network:cidr:parse", Passed: true, Message: "no scope configured"}
	}
	cidrs := strings.Split(scope, ",")
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return CheckResult{
				NodeID:  nodeID,
				Check:   "network:cidr:parse",
				Passed:  false,
				Message: fmt.Sprintf("invalid CIDR: %s", cidr),
				Hint:    "Use notation like 192.168.1.0/24 or 10.0.0.0/8",
			}
		}
	}
	return CheckResult{NodeID: nodeID, Check: "network:cidr:parse", Passed: true, Message: fmt.Sprintf("%d valid CIDR scope(s)", len(cidrs))}
}

// VPSEnvChecker verifies that selected VPS provider tokens are set.
type VPSEnvChecker struct{}

func (c *VPSEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	providers := toStrSlice(value)
	if len(providers) == 0 {
		return CheckResult{NodeID: nodeID, Check: "vps:env:check", Passed: true, Message: "no VPS providers selected"}
	}
	envMap := map[string]string{
		"hetzner":      "KITE_HETZNER_TOKEN",
		"digitalocean": "KITE_DIGITALOCEAN_TOKEN",
		"vultr":        "KITE_VULTR_TOKEN",
		"linode":       "KITE_LINODE_TOKEN",
		"scaleway":     "KITE_SCALEWAY_TOKEN",
		"ovhcloud":     "KITE_OVHCLOUD_TOKEN",
		"upcloud":      "KITE_UPCLOUD_TOKEN",
		"kamatera":     "KITE_KAMATERA_TOKEN",
		"hostinger":    "KITE_HOSTINGER_TOKEN",
	}
	var missing []string
	for _, p := range providers {
		envVar, ok := envMap[p]
		if !ok {
			continue
		}
		if os.Getenv(envVar) == "" {
			missing = append(missing, envVar)
		}
	}
	if len(missing) > 0 {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "vps:env:check",
			Passed:  false,
			Message: fmt.Sprintf("missing env vars: %s", strings.Join(missing, ", ")),
			Hint:    fmt.Sprintf("export %s=<your-token>", missing[0]),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "vps:env:check", Passed: true, Message: "all VPS provider tokens set"}
}

// MDMEnvChecker verifies MDM provider environment variables.
type MDMEnvChecker struct{}

func (c *MDMEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	provider, ok := value.(string)
	if !ok || provider == "none" || provider == "" {
		return CheckResult{NodeID: nodeID, Check: "mdm:env:check", Passed: true, Message: "no MDM provider"}
	}
	envMap := map[string][]string{
		"intune": {"KITE_INTUNE_TENANT_ID", "KITE_INTUNE_CLIENT_ID", "KITE_INTUNE_CLIENT_SECRET"},
		"jamf":   {"KITE_JAMF_URL", "KITE_JAMF_USER", "KITE_JAMF_PASSWORD"},
		"sccm":   {"KITE_SCCM_SERVER", "KITE_SCCM_USER", "KITE_SCCM_PASSWORD"},
	}
	vars, ok := envMap[provider]
	if !ok {
		return CheckResult{NodeID: nodeID, Check: "mdm:env:check", Passed: true, Message: "unknown provider, skipping"}
	}
	var missing []string
	for _, v := range vars {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "mdm:env:check",
			Passed:  false,
			Message: fmt.Sprintf("missing env vars: %s", strings.Join(missing, ", ")),
			Hint:    fmt.Sprintf("export %s=<value>", missing[0]),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "mdm:env:check", Passed: true, Message: fmt.Sprintf("%s credentials set", provider)}
}

// CMDBEnvChecker verifies CMDB provider environment variables.
type CMDBEnvChecker struct{}

func (c *CMDBEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	provider, ok := value.(string)
	if !ok || provider == "none" || provider == "" {
		return CheckResult{NodeID: nodeID, Check: "cmdb:env:check", Passed: true, Message: "no CMDB provider"}
	}
	envMap := map[string][]string{
		"netbox":     {"KITE_NETBOX_URL", "KITE_NETBOX_TOKEN"},
		"servicenow": {"KITE_SNOW_INSTANCE", "KITE_SNOW_USER", "KITE_SNOW_PASSWORD"},
	}
	vars, ok := envMap[provider]
	if !ok {
		return CheckResult{NodeID: nodeID, Check: "cmdb:env:check", Passed: true, Message: "unknown provider, skipping"}
	}
	var missing []string
	for _, v := range vars {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "cmdb:env:check",
			Passed:  false,
			Message: fmt.Sprintf("missing env vars: %s", strings.Join(missing, ", ")),
			Hint:    fmt.Sprintf("export %s=<value>", missing[0]),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "cmdb:env:check", Passed: true, Message: fmt.Sprintf("%s credentials set", provider)}
}

// FileExistsChecker verifies that a referenced file path exists.
type FileExistsChecker struct{}

func (c *FileExistsChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	path, ok := value.(string)
	if !ok || path == "" {
		return CheckResult{NodeID: nodeID, Check: "file:exists", Passed: true, Message: "no file configured"}
	}
	_, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "file:exists",
			Passed:  false,
			Message: fmt.Sprintf("file not found: %s", path),
			Hint:    "Check the path and ensure the file exists",
		}
	}
	return CheckResult{NodeID: nodeID, Check: "file:exists", Passed: true, Message: fmt.Sprintf("%s exists", path)}
}

// TLSConnectChecker attempts a TCP connection to the endpoint.
type TLSConnectChecker struct{}

func (c *TLSConnectChecker) Check(ctx context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	addr, ok := value.(string)
	if !ok || addr == "" {
		return CheckResult{NodeID: nodeID, Check: "endpoint:tls:connect", Passed: true, Message: "no endpoint configured"}
	}
	// Add default port if missing.
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "endpoint:tls:connect",
			Passed:  false,
			Message: fmt.Sprintf("TCP connect failed: %s", err),
			Hint:    "Check the endpoint address and ensure it is reachable",
		}
	}
	_ = conn.Close()
	return CheckResult{NodeID: nodeID, Check: "endpoint:tls:connect", Passed: true, Message: fmt.Sprintf("TCP connect to %s OK", addr)}
}

// EnrollChecker is a placeholder that validates enrollment token format.
type EnrollChecker struct{}

func (c *EnrollChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	token, ok := value.(string)
	if !ok || token == "" {
		return CheckResult{NodeID: nodeID, Check: "endpoint:enroll", Passed: true, Message: "no enrollment token, skipping"}
	}
	// Basic format check: tokens should be non-trivial length.
	if len(token) < 8 {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "endpoint:enroll",
			Passed:  false,
			Message: "enrollment token too short",
			Hint:    "Enrollment tokens are typically 32+ characters",
		}
	}
	return CheckResult{NodeID: nodeID, Check: "endpoint:enroll", Passed: true, Message: "enrollment token format OK"}
}

// OTELHealthChecker checks OTEL collector reachability.
type OTELHealthChecker struct{}

func (c *OTELHealthChecker) Check(ctx context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	endpoint, ok := value.(string)
	if !ok || endpoint == "" {
		return CheckResult{NodeID: nodeID, Check: "otel:health:check", Passed: true, Message: "no OTEL endpoint configured"}
	}
	// Extract host:port from the endpoint URL.
	addr := endpoint
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	if !strings.Contains(addr, ":") {
		addr += ":4318"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "otel:health:check",
			Passed:  false,
			Message: fmt.Sprintf("OTEL Collector unreachable: %s", err),
			Hint:    "Ensure the OTEL Collector is running and the endpoint is correct",
		}
	}
	_ = conn.Close()
	return CheckResult{NodeID: nodeID, Check: "otel:health:check", Passed: true, Message: fmt.Sprintf("OTEL Collector at %s reachable", endpoint)}
}

// TunnelBinaryChecker verifies that the selected tunnel binary exists in PATH.
type TunnelBinaryChecker struct{}

func (c *TunnelBinaryChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	provider, ok := value.(string)
	if !ok || provider == "" {
		return CheckResult{NodeID: nodeID, Check: "tunnel:binary:available", Passed: true, Message: "no tunnel provider selected"}
	}

	// Map provider name to binary name (frp uses frpc).
	binary := provider
	if provider == "frp" {
		binary = "frpc"
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "tunnel:binary:available",
			Passed:  false,
			Message: fmt.Sprintf("%s not found in PATH", binary),
			Hint:    fmt.Sprintf("Install %s or add it to your PATH", provider),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "tunnel:binary:available", Passed: true, Message: fmt.Sprintf("%s found at %s", provider, path)}
}

// TunnelAuthChecker verifies that the tunnel auth token env var is set and non-empty.
type TunnelAuthChecker struct{}

func (c *TunnelAuthChecker) Check(_ context.Context, nodeID string, value any, resolved map[string]any) CheckResult {
	envVar, ok := value.(string)
	if !ok || envVar == "" {
		return CheckResult{NodeID: nodeID, Check: "tunnel:auth:valid", Passed: true, Message: "no auth required"}
	}

	// Check if the provider actually requires auth.
	provider, _ := resolved["connectivity.tunnel.provider"].(string)
	authOptional := provider == "cloudflared" || provider == "bore"
	if authOptional && os.Getenv(envVar) == "" {
		return CheckResult{NodeID: nodeID, Check: "tunnel:auth:valid", Passed: true, Message: fmt.Sprintf("auth optional for %s, skipped", provider)}
	}

	if os.Getenv(envVar) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "tunnel:auth:valid",
			Passed:  false,
			Message: fmt.Sprintf("env var %s is not set", envVar),
			Hint:    fmt.Sprintf("export %s=<your-token>", envVar),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "tunnel:auth:valid", Passed: true, Message: fmt.Sprintf("%s is set", envVar)}
}

// TunnelPortChecker verifies that the local tunnel port is available.
type TunnelPortChecker struct{}

func (c *TunnelPortChecker) Check(ctx context.Context, nodeID string, _ any, resolved map[string]any) CheckResult {
	// Default port from RFC.
	port := "14318"

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ":"+port)
	if err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "tunnel:port:free",
			Passed:  false,
			Message: fmt.Sprintf("port %s is in use", port),
			Hint:    "Change connectivity.tunnel.local_port or stop the process using the port",
		}
	}
	_ = ln.Close()
	return CheckResult{NodeID: nodeID, Check: "tunnel:port:free", Passed: true, Message: fmt.Sprintf("port %s available", port)}
}

func toStrSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, elem := range s {
			if str, ok := elem.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
