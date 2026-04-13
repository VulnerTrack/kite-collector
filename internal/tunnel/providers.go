package tunnel

import (
	"fmt"
	"os"
	"strings"
)

// BuildCommand returns the full argument list (binary + args) for the given
// tunnel provider. The returned slice's first element is the binary name.
// Returns nil for unsupported providers.
//
// Auth tokens are read from the environment variable named by authTokenEnv
// at call time. Providers that require CLI-arg tokens (e.g., ngrok --authtoken)
// will have the token embedded in the args; all others use env-var passthrough.
func BuildCommand(provider ProviderName, target string, localPort uint16, authTokenEnv string, extraArgs []string) []string {
	var args []string

	switch provider {
	case ProviderNgrok:
		args = ngrokCmd(target, localPort, authTokenEnv)
	case ProviderCloudflared:
		args = cloudflaredCmd(target, localPort)
	case ProviderBore:
		args = boreCmd(target, localPort)
	case ProviderTailscale:
		args = tailscaleCmd(localPort)
	case ProviderFRP:
		args = frpCmd(target, localPort, authTokenEnv)
	case ProviderRathole:
		args = ratholeCmd(target, localPort)
	default:
		return nil
	}

	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}

	return args
}

// ngrokCmd builds: ngrok tcp <local_port> --remote-addr=<target> --authtoken=<token> --log=stdout --log-format=json
func ngrokCmd(target string, localPort uint16, authTokenEnv string) []string {
	args := []string{
		"ngrok", "tcp",
		fmt.Sprintf("%d", localPort),
		fmt.Sprintf("--remote-addr=%s", target),
		"--log=stdout",
		"--log-format=json",
	}

	if token := envToken(authTokenEnv); token != "" {
		args = append(args, fmt.Sprintf("--authtoken=%s", token))
	}

	return args
}

// cloudflaredCmd builds: cloudflared access tcp --hostname <target> --url localhost:<local_port>
func cloudflaredCmd(target string, localPort uint16) []string {
	return []string{
		"cloudflared", "access", "tcp",
		"--hostname", target,
		"--url", fmt.Sprintf("localhost:%d", localPort),
	}
}

// boreCmd builds: bore local <local_port> --to <target_host> --port <target_port>
func boreCmd(target string, localPort uint16) []string {
	host, port := splitHostPort(target)
	if port == "" {
		port = "443"
	}
	return []string{
		"bore", "local",
		fmt.Sprintf("%d", localPort),
		"--to", host,
		"--port", port,
	}
}

// tailscaleCmd builds: tailscale funnel --bg <local_port>
func tailscaleCmd(localPort uint16) []string {
	return []string{
		"tailscale", "funnel",
		"--bg",
		fmt.Sprintf("%d", localPort),
	}
}

// frpCmd builds: frpc tcp --server_addr=<target> --local_port=<local_port> --token=<token>
func frpCmd(target string, localPort uint16, authTokenEnv string) []string {
	args := []string{
		"frpc", "tcp",
		fmt.Sprintf("--server_addr=%s", target),
		fmt.Sprintf("--local_port=%d", localPort),
	}

	if token := envToken(authTokenEnv); token != "" {
		args = append(args, fmt.Sprintf("--token=%s", token))
	}

	return args
}

// ratholeCmd builds: rathole client --server <target> --local <local_port>
func ratholeCmd(target string, localPort uint16) []string {
	return []string{
		"rathole", "client",
		"--server", target,
		"--local", fmt.Sprintf("%d", localPort),
	}
}

// envToken reads an auth token from the named environment variable.
// Returns empty string if the variable is unset or the name is empty.
func envToken(envVar string) string {
	if envVar == "" {
		return ""
	}
	return os.Getenv(envVar)
}

// splitHostPort splits a "host:port" string. If no port is present, port is
// returned as empty string (not an error, unlike net.SplitHostPort).
func splitHostPort(addr string) (host, port string) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, ""
	}
	return addr[:idx], addr[idx+1:]
}
