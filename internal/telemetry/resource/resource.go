// Package resource builds the OTel resource attribute set the agent attaches
// to every signal, per RFC-0115 §4.2. The output conforms to the contract
// declared in internal/telemetry/contract.
//
// Host detection (host.id, host.name, os.*) is delegated to a small policy
// engine in policy.go: ordered detection rules, first-match-wins. Adding a
// new source (macOS sw_vers, Windows registry, container metadata) is one
// new policy registered ahead of the runtime fallback.
package resource

import (
	"os"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// Config holds the externally-supplied inputs to the resource builder. The
// host-derived attributes (host.*, os.*) are filled in by Build itself.
type Config struct {
	// ServiceVersion is the agent build version.
	ServiceVersion string
	// TenantID is the tenant the agent enrolled into. Client-asserted; the
	// Collector overrides this from the mTLS Subject CN per RFC-0115 §5.1.
	TenantID string
	// Environment is one of production|staging|pilot|development.
	Environment string
	// AgentID is the persistent agent identity (UUIDv7) and becomes both
	// service.instance.id and agent.id on the resource.
	AgentID uuid.UUID
}

// Build returns the resource attribute map per RFC-0115 §4.2. Every key in
// contract.RequiredResourceAttributes is populated; host- and OS-derived
// fields fall back to "unknown" when detection fails so the attribute is
// always present (the contract requires it).
func Build(cfg Config) map[string]string {
	hostID := detectHostID()
	hostname := detectHostname()
	osType, osName, osVersion := defaultOSDetector().Detect()

	env := cfg.Environment
	if env == "" {
		env = "production"
	}

	tenant := cfg.TenantID
	if tenant == "" {
		tenant = "unknown"
	}

	return map[string]string{
		string(contract.ResAttrServiceName):       contract.ServiceName,
		string(contract.ResAttrServiceVersion):    cfg.ServiceVersion,
		string(contract.ResAttrServiceNamespace):  contract.ServiceNamespace,
		string(contract.ResAttrServiceInstanceID): cfg.AgentID.String(),
		string(contract.ResAttrHostID):            hostID,
		string(contract.ResAttrHostName):          hostname,
		string(contract.ResAttrHostArch):          runtime.GOARCH,
		string(contract.ResAttrOSType):            osType,
		string(contract.ResAttrOSName):            osName,
		string(contract.ResAttrOSVersion):         osVersion,
		string(contract.ResAttrAgentID):           cfg.AgentID.String(),
		string(contract.ResAttrAgentType):         contract.AgentType,
		string(contract.ResAttrTenantID):          tenant,
		string(contract.ResAttrDeploymentEnv):     env,
		string(contract.ResAttrContractVersion):   contract.Version,
	}
}

// detectHostID reads the OS machine identifier. Linux uses /etc/machine-id;
// macOS and Windows currently fall back to the hostname (a richer detector
// lives in internal/identity/fingerprint.go but we deliberately do not
// import it here to keep this package leaf-level).
func detectHostID() string {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func detectHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func splitOSReleaseLine(line string) (key, value string) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", ""
	}
	key = line[:idx]
	value = strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"'`)
	return key, value
}
