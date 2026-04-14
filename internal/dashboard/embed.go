//go:build !dev

package dashboard

import "embed"

// staticFS contains all static assets compiled into the binary.
// At runtime there is no filesystem dependency.
//
//go:embed static/*
var staticFS embed.FS
