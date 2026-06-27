package autodiscovery

import (
	"fmt"
	"os"
	"strings"
)

// probeSocket checks whether a Unix socket exists at path.
func probeSocket(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Type() == os.ModeSocket
}

// probeAllSockets checks all known socket paths across registered services
// and returns a DiscoveredService for each accessible socket.
func probeAllSockets(services []ServiceSignature) []DiscoveredService {
	uid := os.Getuid()
	var results []DiscoveredService

	for _, svc := range services {
		for _, tmpl := range svc.SocketPaths {
			path := expandSocketPath(tmpl, uid)
			if !probeSocket(path) {
				continue
			}
			status, missing := determineStatus(svc)
			results = append(results, DiscoveredService{
				Name:        svc.Name,
				DisplayName: svc.DisplayName,
				Endpoint:    path,
				Method:      "socket",
				Status:      status,
				Credentials: missing,
				SetupHint:   svc.SetupHint,
			})
			break // one socket per service is enough
		}
	}
	return results
}

// expandSocketPath replaces %d with the given uid.  If the template does not
// contain a format verb, it is returned as-is.
func expandSocketPath(tmpl string, uid int) string {
	if !strings.Contains(tmpl, "%d") {
		return tmpl
	}
	return fmt.Sprintf(tmpl, uid)
}
