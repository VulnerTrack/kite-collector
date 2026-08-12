//go:build windows

package osquery

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/Microsoft/go-winio"
)

// defaultSocketPaths: the kite-collector-osquery MSI installs kite-osqueryd
// with --extensions_socket=\\.\pipe\kite-osquery.em (see cmd/kite-collector/
// wix.wxs); a stock osqueryd uses \\.\pipe\osquery.em.
var defaultSocketPaths = []string{
	`\\.\pipe\kite-osquery.em`,
	`\\.\pipe\osquery.em`,
}

// platformDial connects to the extensions surface. osquery on Windows serves
// Thrift over a named pipe; unix paths are still dialed as AF_UNIX, which
// Windows 10+ supports, so an explicitly configured unix socket keeps working.
func platformDial(ctx context.Context, path string) (net.Conn, error) {
	if strings.HasPrefix(path, `\\.\pipe\`) {
		return winio.DialPipeContext(ctx, path)
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", path) //#nosec G704 -- socket path from user config
}

// detectSocket returns the first default pipe that exists, or "".
func detectSocket() string {
	for _, p := range defaultSocketPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
