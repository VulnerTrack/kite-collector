package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// runner is the exec seam. Every enumerator that shells out to a VPN
// control binary (tailscale, wg, zerotier-cli, netbird, swanctl) routes
// through this type so tests can inject a fixture without spawning a
// process. Mirrors the convention in internal/discovery/agent/vpn.
type runner func(ctx context.Context, binary string, args ...string) ([]byte, error)

// defaultRunner executes binary with args and returns stdout. binary is
// always exec.LookPath-resolved (or an operator-supplied absolute path)
// before reaching this seam and args are fixed literals, so there is no
// injection vector.
func defaultRunner(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...) //#nosec G204 -- binary is LookPath-resolved; args are fixed literals
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", binary, err)
	}
	return out, nil
}

// lookPather resolves a binary name to an absolute path. exec.LookPath in
// production; a stub in tests.
type lookPather func(string) (string, error)

// fileReader reads a whole file. os.ReadFile in production; a stub in
// tests so enumerators that parse config/state files stay hermetic.
type fileReader func(string) ([]byte, error)

// osReadFile is the production fileReader.
func osReadFile(p string) ([]byte, error) {
	data, err := os.ReadFile(p) //#nosec G304 -- caller passes fixed system paths
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	return data, nil
}
