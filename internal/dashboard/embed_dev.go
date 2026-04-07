//go:build dev

package dashboard

import "os"

// In dev mode, serve static files from disk for live editing.
// Build with: go run -tags dev ./cmd/kite-collector dashboard
var staticFS = os.DirFS("internal/dashboard/static")
