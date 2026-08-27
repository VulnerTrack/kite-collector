// Package osqueryconf carries the osquery configuration kite writes when it
// registers a kite-osqueryd service against an osqueryd the operator already
// installed (macOS today — see internal/installer/osquery_host.go).
//
// The packaged lanes do NOT read these files: the deb ships
// packaging/deb/osquery.{conf,flags} as dpkg conffiles and the MSI ships
// configs/osquery/osquery.{conf,flags} as MSI components, because a package
// manager must own the files it installs. This package is for the lane where
// nothing else owns them — the collector writes them itself, so they have to
// travel inside the binary.
package osqueryconf

import _ "embed"

//go:embed osquery.darwin.conf
var darwinConf []byte

//go:embed osquery.darwin.flags
var darwinFlags []byte

// DarwinConf returns the macOS osquery.conf contents.
func DarwinConf() []byte { return darwinConf }

// DarwinFlags returns the macOS osquery.flags contents.
func DarwinFlags() []byte { return darwinFlags }
