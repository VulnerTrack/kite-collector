// Package tunnel implements auto-detection, provisioning, and lifecycle
// management of reverse tunnel subprocesses. It enables kite-collector agents
// behind NAT or restrictive firewalls to reach the SaaS backend by leveraging
// user-installed tunnel tools (ngrok, cloudflared, bore, tailscale, frp, rathole).
//
// All tunnel binaries are resolved via exec.LookPath — no arbitrary path
// execution. Auth tokens are read from environment variables only.
package tunnel

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProviderName enumerates the supported tunnel providers.
type ProviderName string

const (
	ProviderNgrok       ProviderName = "ngrok"
	ProviderCloudflared ProviderName = "cloudflared"
	ProviderBore        ProviderName = "bore"
	ProviderTailscale   ProviderName = "tailscale"
	ProviderFRP         ProviderName = "frp"
	ProviderRathole     ProviderName = "rathole"
)

// KnownProviders lists all providers that Detect() will scan for.
var KnownProviders = []ProviderMeta{
	{Name: ProviderNgrok, Binary: "ngrok", AuthRequired: true, AuthEnvVar: "KITE_TUNNEL_AUTH_TOKEN", SupportsTCP: true, SupportsHTTP: true},
	{Name: ProviderCloudflared, Binary: "cloudflared", AuthRequired: false, AuthEnvVar: "", SupportsTCP: true, SupportsHTTP: true},
	{Name: ProviderBore, Binary: "bore", AuthRequired: false, AuthEnvVar: "", SupportsTCP: true, SupportsHTTP: false},
	{Name: ProviderTailscale, Binary: "tailscale", AuthRequired: true, AuthEnvVar: "", SupportsTCP: true, SupportsHTTP: true},
	{Name: ProviderFRP, Binary: "frpc", AuthRequired: false, AuthEnvVar: "KITE_TUNNEL_AUTH_TOKEN", SupportsTCP: true, SupportsHTTP: true},
	{Name: ProviderRathole, Binary: "rathole", AuthRequired: true, AuthEnvVar: "", SupportsTCP: true, SupportsHTTP: false},
}

// ProviderMeta holds static metadata about a tunnel provider.
type ProviderMeta struct {
	Name         ProviderName
	Binary       string
	AuthEnvVar   string
	AuthRequired bool
	SupportsTCP  bool
	SupportsHTTP bool
}

// TunnelProvider represents a detected tunnel binary on the agent host.
type TunnelProvider struct {
	EntityID     uuid.UUID    `json:"entity_id"`
	Name         ProviderName `json:"name"`
	BinaryPath   string       `json:"binary_path"`
	Version      string       `json:"version,omitempty"`
	AuthEnvVar   string       `json:"auth_env_var,omitempty"`
	DetectedAt   time.Time    `json:"detected_at"`
	AuthRequired bool         `json:"auth_required"`
	SupportsTCP  bool         `json:"supports_tcp"`
	SupportsHTTP bool         `json:"supports_http"`
}

// Detect scans the system PATH for known tunnel binaries and returns a list
// of detected providers. Detection is read-only — only exec.LookPath and
// optional version queries are performed.
func Detect(logger *slog.Logger) []TunnelProvider {
	var found []TunnelProvider
	now := time.Now()

	for _, meta := range KnownProviders {
		path, err := exec.LookPath(meta.Binary)
		if err != nil {
			logger.Debug("tunnel provider not found", "provider", meta.Name, "binary", meta.Binary)
			continue
		}

		provider := TunnelProvider{
			EntityID:     uuid.Must(uuid.NewV7()),
			Name:         meta.Name,
			BinaryPath:   path,
			AuthRequired: meta.AuthRequired,
			AuthEnvVar:   meta.AuthEnvVar,
			SupportsTCP:  meta.SupportsTCP,
			SupportsHTTP: meta.SupportsHTTP,
			DetectedAt:   now,
		}

		// Best-effort version detection.
		provider.Version = detectVersion(path, meta.Name)

		logger.Info("tunnel provider detected",
			"provider", meta.Name,
			"path", path,
			"version", provider.Version,
		)
		found = append(found, provider)
	}

	return found
}

// DetectProvider looks up a single provider by name. Returns nil if not found.
func DetectProvider(name ProviderName, logger *slog.Logger) *TunnelProvider {
	for _, p := range Detect(logger) {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

// detectVersion runs `<binary> version` (or provider-specific variant) and
// extracts the version string. Returns empty string on any failure.
func detectVersion(binaryPath string, name ProviderName) string {
	var args []string
	switch name {
	case ProviderNgrok:
		args = []string{"version"}
	case ProviderCloudflared:
		args = []string{"version"}
	case ProviderBore:
		args = []string{"--version"}
	case ProviderTailscale:
		args = []string{"version"}
	case ProviderFRP:
		args = []string{"--version"}
	case ProviderRathole:
		args = []string{"--version"}
	default:
		return ""
	}

	out, err := exec.Command(binaryPath, args...).Output() //#nosec G204 -- binaryPath from LookPath, args are static
	if err != nil {
		return ""
	}

	// Take the first non-empty line as version info.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return sanitizeVersion(line)
		}
	}
	return ""
}

// sanitizeVersion trims common prefixes and keeps only the meaningful part.
func sanitizeVersion(raw string) string {
	// Cap at 128 chars to avoid storing garbage.
	if len(raw) > 128 {
		raw = raw[:128]
	}
	return fmt.Sprintf("%s", strings.TrimSpace(raw))
}
