//go:build darwin

package osquery

// defaultSocketPaths are the macOS extensions-socket candidates, most specific
// first.
//
// The kite-namespaced daemon does NOT reuse the Linux
// /run/kite-osquery/kite-osquery.em path: macOS has no /run at all, and its
// /var/run is wiped on every boot, so a socket directory created once at
// install time would vanish after the first restart and kite-osqueryd would
// fail to bind. /var/kite-osquery is the macOS analogue of the /var/osquery
// directory osquery's own pkg creates — persistent, root-owned, and namespaced
// so it can never collide with a standalone osquery install
// (internal/installer.OsqueryDarwinSocket is the other end of this contract).
//
// /var/osquery/osquery.em is where a stock osqueryd lands, whether it came
// from the official osquery pkg or `brew install --cask osquery`; both install
// the same payload. Discovery therefore works against an operator's own
// osquery daemon with no kite-side configuration at all.
var defaultSocketPaths = []string{
	"/var/kite-osquery/kite-osquery.em",
	"/var/osquery/osquery.em",
	"/var/run/osquery/osquery.em",
}
