//go:build !windows && !darwin

package osquery

// defaultSocketPaths are where a root osqueryd puts its extensions socket on
// Linux (and the tier-2 BSDs). The kite-collector-osquery deb runs
// kite-osqueryd with --extensions_socket=/run/kite-osquery/kite-osquery.em
// (see packaging/deb/kite-osqueryd.service), mirroring the Windows MSI's
// \\.\pipe\kite-osquery.em contract; the rest are stock osqueryd locations.
var defaultSocketPaths = []string{
	"/run/kite-osquery/kite-osquery.em",
	"/var/osquery/osquery.em",
	"/var/run/osquery/osquery.em",
}
