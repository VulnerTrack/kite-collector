package ldap

import (
	"fmt"
	"strings"
)

// Default config values (RFC-0121 §5.4 / §10.2).
const (
	defaultTLSMode             = "ldaps"
	defaultBindPasswordEnvVar  = "KITE_LDAP_BIND_PASSWORD" //#nosec G101 -- env var name, not credential value
	defaultPageSize            = 1000
	defaultTimeoutSeconds      = 300
	defaultStaleThresholdDays  = 90
	defaultMaxObjects          = 100_000
	defaultCollectUsers        = false
	defaultCollectGroups       = true
	defaultCollectOUs          = true
	defaultCollectGPOs         = false
	maxAllowedPageSize         = 5000
	maxAllowedObjectsHardLimit = 1_000_000
)

// dcEndpoint identifies a single domain controller.
type dcEndpoint struct {
	host string
	port int
}

// ldapConfig is the fully parsed source configuration.
type ldapConfig struct {
	tlsMode            string
	tlsCAFile          string
	bindDN             string
	bindPasswordEnvVar string
	baseDN             string
	domainControllers  []dcEndpoint
	pageSize           uint32
	timeoutSeconds     int
	staleThresholdDays int
	maxObjects         int
	enabled            bool
	tlsSkipVerify      bool
	collectUsers       bool
	collectGroups      bool
	collectOUs         bool
	collectGPOs        bool
}

// parseConfig translates the source-specific config map produced by viper
// into a typed ldapConfig. Unknown / missing keys fall back to the defaults
// declared in the constant block above.
func parseConfig(cfg map[string]any) (*ldapConfig, error) {
	// pageSize is later validated to be in [1, maxAllowedPageSize]; clamp
	// any negative or oversize int input to the default before the uint32
	// cast so G115 has no chance of firing on the conversion. validate()
	// will still reject 0 explicitly via the range check below.
	pageSize := intCfg(cfg, "page_size", defaultPageSize)
	if pageSize < 0 || pageSize > maxAllowedPageSize {
		pageSize = defaultPageSize
	}

	c := &ldapConfig{
		enabled:            boolCfg(cfg, "enabled", false),
		tlsMode:            strCfg(cfg, "tls_mode", defaultTLSMode),
		tlsSkipVerify:      boolCfg(cfg, "tls_skip_verify", false),
		tlsCAFile:          strCfg(cfg, "tls_ca_file", ""),
		bindDN:             strCfg(cfg, "bind_dn", ""),
		bindPasswordEnvVar: strCfg(cfg, "bind_password_env", defaultBindPasswordEnvVar),
		baseDN:             strCfg(cfg, "base_dn", ""),
		pageSize:           uint32(pageSize), //nolint:gosec // bounded above to [0, maxAllowedPageSize]
		timeoutSeconds:     intCfg(cfg, "timeout_seconds", defaultTimeoutSeconds),
		staleThresholdDays: intCfg(cfg, "stale_threshold_days", defaultStaleThresholdDays),
		maxObjects:         intCfg(cfg, "max_objects", defaultMaxObjects),
		collectUsers:       boolCfg(cfg, "collect_users", defaultCollectUsers),
		collectGroups:      boolCfg(cfg, "collect_groups", defaultCollectGroups),
		collectOUs:         boolCfg(cfg, "collect_ous", defaultCollectOUs),
		collectGPOs:        boolCfg(cfg, "collect_gpos", defaultCollectGPOs),
	}

	dcs, err := parseDCs(cfg["domain_controllers"], c.tlsMode)
	if err != nil {
		return nil, err
	}
	c.domainControllers = dcs

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// validate enforces the per-field constraints called out in RFC-0121 §5.4.
func (c *ldapConfig) validate() error {
	switch c.tlsMode {
	case "ldaps", "starttls", "none":
	default:
		return fmt.Errorf("invalid tls_mode %q (must be ldaps|starttls|none)", c.tlsMode)
	}
	if c.enabled {
		if c.baseDN == "" {
			return fmt.Errorf("base_dn is required when enabled=true")
		}
		if c.bindDN == "" {
			return fmt.Errorf("bind_dn is required when enabled=true")
		}
		if len(c.domainControllers) == 0 {
			return fmt.Errorf("at least one domain_controllers entry is required")
		}
	}
	if c.pageSize == 0 || c.pageSize > maxAllowedPageSize {
		return fmt.Errorf("page_size must be between 1 and %d (got %d)", maxAllowedPageSize, c.pageSize)
	}
	if c.maxObjects <= 0 || c.maxObjects > maxAllowedObjectsHardLimit {
		return fmt.Errorf("max_objects must be between 1 and %d (got %d)", maxAllowedObjectsHardLimit, c.maxObjects)
	}
	if c.timeoutSeconds <= 0 {
		return fmt.Errorf("timeout_seconds must be positive (got %d)", c.timeoutSeconds)
	}
	return nil
}

// parseDCs converts the loosely-typed domain_controllers config value into
// a typed slice. Each entry is either a {host, port} map or a bare string
// of the form "host:port".
func parseDCs(raw any, tlsMode string) ([]dcEndpoint, error) {
	defaultPort := 636
	if tlsMode != "ldaps" {
		defaultPort = 389
	}

	items, ok := raw.([]any)
	if !ok {
		if raw == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("domain_controllers must be a list (got %T)", raw)
	}

	out := make([]dcEndpoint, 0, len(items))
	for i, item := range items {
		switch v := item.(type) {
		case string:
			host, port, err := splitHostPort(v, defaultPort)
			if err != nil {
				return nil, fmt.Errorf("domain_controllers[%d]: %w", i, err)
			}
			out = append(out, dcEndpoint{host: host, port: port})
		case map[string]any:
			host := strCfg(v, "host", "")
			if host == "" {
				return nil, fmt.Errorf("domain_controllers[%d]: missing host", i)
			}
			port := intCfg(v, "port", defaultPort)
			out = append(out, dcEndpoint{host: host, port: port})
		default:
			return nil, fmt.Errorf("domain_controllers[%d]: unsupported entry type %T", i, item)
		}
	}
	return out, nil
}

// splitHostPort accepts "host", "host:port", or IPv6 "[::1]:port" and
// returns (host, port). host is required.
func splitHostPort(s string, defaultPort int) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty endpoint")
	}
	if !strings.Contains(s, ":") {
		return s, defaultPort, nil
	}
	idx := strings.LastIndex(s, ":")
	host := strings.TrimSuffix(strings.TrimPrefix(s[:idx], "["), "]")
	portStr := s[idx+1:]
	if portStr == "" {
		return host, defaultPort, nil
	}
	port := 0
	for _, r := range portStr {
		if r < '0' || r > '9' {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		port = port*10 + int(r-'0')
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, port, nil
}

func boolCfg(cfg map[string]any, key string, def bool) bool {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key].(bool); ok {
		return v
	}
	return def
}

func intCfg(cfg map[string]any, key string, def int) int {
	if cfg == nil {
		return def
	}
	switch v := cfg[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return def
	}
}

func strCfg(cfg map[string]any, key, def string) string {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key].(string); ok && v != "" {
		return v
	}
	return def
}
