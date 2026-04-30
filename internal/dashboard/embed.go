//go:build !dev

package dashboard

import "embed"

// staticFS contains all static assets compiled into the binary.
// At runtime there is no filesystem dependency. The "all:" prefix and the
// "static/*/*" pattern ensure files inside subdirectories like static/img/
// are embedded too.
//
//go:embed all:static
var staticFS embed.FS
