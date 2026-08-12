//go:build !windows

package osquery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
)

// defaultSocketPaths are where a root osqueryd puts its extensions socket on
// Linux and macOS.
var defaultSocketPaths = []string{
	"/var/osquery/osquery.em",
	"/var/run/osquery/osquery.em",
}

// platformDial connects to a unix-domain extensions socket.
func platformDial(ctx context.Context, path string) (net.Conn, error) {
	if strings.HasPrefix(path, `\\.\pipe\`) {
		return nil, fmt.Errorf("windows named-pipe path %q on a non-windows host", path)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path) //#nosec G704 -- socket path from user config
	if err != nil {
		return nil, fmt.Errorf("dial unix %s: %w", path, err)
	}
	return conn, nil
}

// detectSocket returns the first default extensions socket that exists, or "".
func detectSocket() string {
	for _, p := range defaultSocketPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Type() == os.ModeSocket {
			return p
		}
	}
	return ""
}
