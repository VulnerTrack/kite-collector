package entra

import "fmt"

// Default config values (RFC-0121 §5.4 / §10.2).
const (
	defaultStaleAccountDays    = 90
	defaultMaxUsers            = 50_000
	defaultMaxServicePrincipal = 10_000
	defaultMaxGroups           = 50_000
	defaultMaxDevices          = 50_000
	defaultRequestTimeoutSecs  = 60
	defaultPageSize            = 999
	defaultGraphBaseURL        = "https://graph.microsoft.com"
	defaultTokenBaseURL        = "https://login.microsoftonline.com" //#nosec G101 -- public Microsoft OAuth endpoint URL, not a credential

	hardLimitMaxUsers   = 1_000_000
	hardLimitMaxObjects = 500_000
)

// entraConfig is the fully parsed source-specific configuration.
type entraConfig struct {
	tenantID            string
	clientID            string
	clientSecret        string
	graphBaseURL        string
	tokenBaseURL        string
	staleAccountDays    int
	maxUsers            int
	maxServicePrincipal int
	maxGroups           int
	maxDevices          int
	requestTimeoutSecs  int
	pageSize            int
	enabled             bool
}

// parseConfig translates the source-specific config map produced by viper into
// a typed entraConfig. Unknown / missing keys fall back to the defaults
// declared in the constant block above.
func parseConfig(cfg map[string]any) (*entraConfig, error) {
	c := &entraConfig{
		enabled:             boolCfg(cfg, "enabled", true),
		tenantID:            strCfg(cfg, "tenant_id", ""),
		clientID:            strCfg(cfg, "client_id", ""),
		clientSecret:        strCfg(cfg, "client_secret", ""),
		graphBaseURL:        strCfg(cfg, "graph_base_url", defaultGraphBaseURL),
		tokenBaseURL:        strCfg(cfg, "token_base_url", defaultTokenBaseURL),
		staleAccountDays:    intCfg(cfg, "stale_account_days", defaultStaleAccountDays),
		maxUsers:            intCfg(cfg, "max_users", defaultMaxUsers),
		maxServicePrincipal: intCfg(cfg, "max_service_principals", defaultMaxServicePrincipal),
		maxGroups:           intCfg(cfg, "max_groups", defaultMaxGroups),
		maxDevices:          intCfg(cfg, "max_devices", defaultMaxDevices),
		requestTimeoutSecs:  intCfg(cfg, "request_timeout_seconds", defaultRequestTimeoutSecs),
		pageSize:            intCfg(cfg, "page_size", defaultPageSize),
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// validate enforces the per-field constraints called out in RFC-0121 §5.4.
func (c *entraConfig) validate() error {
	if c.staleAccountDays <= 0 {
		return fmt.Errorf("stale_account_days must be positive (got %d)", c.staleAccountDays)
	}
	if c.maxUsers <= 0 || c.maxUsers > hardLimitMaxUsers {
		return fmt.Errorf("max_users must be between 1 and %d (got %d)", hardLimitMaxUsers, c.maxUsers)
	}
	if c.maxServicePrincipal <= 0 || c.maxServicePrincipal > hardLimitMaxObjects {
		return fmt.Errorf("max_service_principals must be between 1 and %d (got %d)",
			hardLimitMaxObjects, c.maxServicePrincipal)
	}
	if c.maxGroups <= 0 || c.maxGroups > hardLimitMaxObjects {
		return fmt.Errorf("max_groups must be between 1 and %d (got %d)", hardLimitMaxObjects, c.maxGroups)
	}
	if c.maxDevices <= 0 || c.maxDevices > hardLimitMaxObjects {
		return fmt.Errorf("max_devices must be between 1 and %d (got %d)", hardLimitMaxObjects, c.maxDevices)
	}
	if c.requestTimeoutSecs <= 0 {
		return fmt.Errorf("request_timeout_seconds must be positive (got %d)", c.requestTimeoutSecs)
	}
	if c.pageSize <= 0 || c.pageSize > 999 {
		return fmt.Errorf("page_size must be between 1 and 999 (got %d)", c.pageSize)
	}
	return nil
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

// intCfg reads an integer-valued config key. A missing key, an unrecognised
// type, or a non-positive value all fall back to the default — non-positive
// values arrive from mapstructure when the user omits the YAML key entirely
// (Go zero value), and every int config knob this package exposes must be
// strictly positive, so collapsing both cases is safe.
func intCfg(cfg map[string]any, key string, def int) int {
	if cfg == nil {
		return def
	}
	var v int
	switch t := cfg[key].(type) {
	case int:
		v = t
	case int64:
		v = int(t)
	case float64:
		v = int(t)
	default:
		return def
	}
	if v <= 0 {
		return def
	}
	return v
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
