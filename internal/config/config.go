package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration structure.
type Config struct {
	Discovery      DiscoveryConfig      `mapstructure:"discovery"`
	Classification ClassificationConfig `mapstructure:"classification"`
	Connectivity   ConnectivityConfig   `mapstructure:"connectivity"`
	Streaming      StreamingConfig      `mapstructure:"streaming"`
	Postgres       PostgresConfig       `mapstructure:"postgres"`
	Identity       IdentityConfig       `mapstructure:"identity"`
	Fleet          FleetConfig          `mapstructure:"fleet"`
	Endpoints      []EndpointConfig     `mapstructure:"endpoints"`
	LogLevel       string               `mapstructure:"log_level"`
	OutputFormat   string               `mapstructure:"output_format"`
	DataDir        string               `mapstructure:"data_dir"`
	StaleThreshold string               `mapstructure:"stale_threshold"` // duration string like "168h"
	Metrics        MetricsConfig        `mapstructure:"metrics"`
	Audit          AuditConfig          `mapstructure:"audit"`
	Safety         SafetyConfig         `mapstructure:"safety"`
	Posture        PostureConfig        `mapstructure:"posture"`
}

// FleetConfig configures fleet identity and multi-tenant agent routing (RFC-0063).
type FleetConfig struct {
	APIKey            string `mapstructure:"api_key"`            // shared API key for admin endpoints
	TenantID          string `mapstructure:"tenant_id"`          // pre-assigned tenant ID for this agent
	Enabled           bool   `mapstructure:"enabled"`            // master toggle for fleet features
	RequireEnrollment bool   `mapstructure:"require_enrollment"` // require agents to enroll before reporting
	MTLSRequired      bool   `mapstructure:"mtls_required"`      // require mTLS on all endpoints
}

// ConnectivityConfig holds settings for network connectivity aids like tunnels.
type ConnectivityConfig struct {
	Tunnel TunnelConfig `mapstructure:"tunnel"`
}

// TunnelConfig configures the auto-tunnel subsystem. When Enabled is true and
// the backend endpoint is unreachable, the agent provisions a reverse tunnel
// using the specified provider binary.
type TunnelConfig struct {
	Provider     string   `mapstructure:"provider"`             // ngrok, cloudflared, bore, tailscale, frp, rathole
	Target       string   `mapstructure:"target"`               // backend endpoint to tunnel to
	AuthTokenEnv string   `mapstructure:"auth_token_env"`       // env var containing auth token
	BackoffBase  string   `mapstructure:"restart_backoff_base"` // exponential backoff base (e.g., "5s")
	BackoffMax   string   `mapstructure:"restart_backoff_max"`  // backoff cap (e.g., "5m")
	ExtraArgs    []string `mapstructure:"extra_args"`           // additional CLI args
	LocalPort    int      `mapstructure:"local_port"`           // local listen port for tunnel
	RestartMax   int      `mapstructure:"restart_max"`          // max restarts (0 = unlimited)
	Enabled      bool     `mapstructure:"enabled"`              // master toggle (default: false)
}

// TunnelBackoffBase parses the BackoffBase duration string. Falls back to 5s.
func (t *TunnelConfig) TunnelBackoffBase() time.Duration {
	if t.BackoffBase == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(t.BackoffBase)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// TunnelBackoffMax parses the BackoffMax duration string. Falls back to 5m.
func (t *TunnelConfig) TunnelBackoffMax() time.Duration {
	if t.BackoffMax == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(t.BackoffMax)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// IdentityConfig configures the agent's persistent identity and credential storage.
type IdentityConfig struct {
	DataDir    string `mapstructure:"data_dir"`    // stores keypair + per-endpoint certs
	KeyBackend string `mapstructure:"key_backend"` // "auto" | "tpm" | "keyring" | "file"
}

// EndpointConfig describes a single backend endpoint the agent connects to.
type EndpointConfig struct {
	Health     HealthConfig     `mapstructure:"health"`
	Name       string           `mapstructure:"name"`
	Address    string           `mapstructure:"address"`
	TLS        TLSConfig        `mapstructure:"tls"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Routes     []string         `mapstructure:"routes"`
	Priority   int              `mapstructure:"priority"`
}

// EncryptionConfig configures JWE payload encryption for an endpoint.
type EncryptionConfig struct {
	ServerJWKURL      string `mapstructure:"server_jwk_url"`
	Algorithm         string `mapstructure:"algorithm"`
	ContentEncryption string `mapstructure:"content_encryption"`
	Enabled           bool   `mapstructure:"enabled"`
}

// HealthConfig configures endpoint health checking.
type HealthConfig struct {
	Interval string `mapstructure:"interval"` // duration string like "30s"
	Timeout  string `mapstructure:"timeout"`  // duration string like "5s"
}

// HealthIntervalDuration parses the Interval string. Falls back to 30s.
func (h *HealthConfig) HealthIntervalDuration() time.Duration {
	if h.Interval == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(h.Interval)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// HealthTimeoutDuration parses the Timeout string. Falls back to 5s.
func (h *HealthConfig) HealthTimeoutDuration() time.Duration {
	if h.Timeout == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(h.Timeout)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// SafetyConfig holds runtime safety settings.
type SafetyConfig struct {
	ScanDeadline     string               `mapstructure:"scan_deadline"` // duration like "30m"
	CircuitBreaker   CircuitBreakerConfig `mapstructure:"circuit_breaker"`
	MaxResponseBytes int64                `mapstructure:"max_response_bytes"` // 0 = unlimited
	MaxRequestBytes  int64                `mapstructure:"max_request_bytes"`
}

// CircuitBreakerConfig configures the per-source circuit breaker.
type CircuitBreakerConfig struct {
	Cooldown         string `mapstructure:"cooldown"` // duration like "5m"
	FailureThreshold int    `mapstructure:"failure_threshold"`
	SuccessThreshold int    `mapstructure:"success_threshold"`
}

// ScanDeadlineDuration parses the Safety.ScanDeadline string. Falls back
// to 30 minutes if empty or invalid.
func (c *Config) ScanDeadlineDuration() time.Duration {
	if c.Safety.ScanDeadline == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(c.Safety.ScanDeadline)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// CircuitBreakerCooldown parses the cooldown duration string. Falls back
// to 5 minutes if empty or invalid.
func (c *Config) CircuitBreakerCooldown() time.Duration {
	if c.Safety.CircuitBreaker.Cooldown == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(c.Safety.CircuitBreaker.Cooldown)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// DiscoveryConfig holds configuration for all discovery sources.
type DiscoveryConfig struct {
	Sources map[string]SourceConfig `mapstructure:"sources"`
}

// SourceConfig holds configuration for a single discovery source.
//
// Field order is intentionally optimised for the fieldalignment govet
// analyser; the on-disk YAML order is dictated by mapstructure tags, not
// Go declaration order.
type SourceConfig struct {
	TLSCAFile          string   `mapstructure:"tls_ca_file"`
	BindPasswordEnv    string   `mapstructure:"bind_password_env"`
	BindDN             string   `mapstructure:"bind_dn"`
	BaseDN             string   `mapstructure:"base_dn"`
	TLSMode            string   `mapstructure:"tls_mode"`
	Timeout            string   `mapstructure:"timeout"`
	AssumeRole         string   `mapstructure:"assume_role"`
	Project            string   `mapstructure:"project"`
	SubscriptionID     string   `mapstructure:"subscription_id"`
	Host               string   `mapstructure:"host"`
	Endpoint           string   `mapstructure:"endpoint"`
	Site               string   `mapstructure:"site"`
	Community          string   `mapstructure:"community"`
	Regions            []string `mapstructure:"regions"`
	Paths              []string `mapstructure:"paths"`
	Scope              []string `mapstructure:"scope"`
	DomainControllers  []string `mapstructure:"domain_controllers"`
	TCPPorts           []int    `mapstructure:"tcp_ports"`
	MaxObjects         int      `mapstructure:"max_objects"`
	MaxConcurrent      int      `mapstructure:"max_concurrent"`
	MaxDepth           int      `mapstructure:"max_depth"`
	PageSize           int      `mapstructure:"page_size"`
	StaleThresholdDays int      `mapstructure:"stale_threshold_days"`
	// Entra-specific (RFC-0121 §5.4); harmless when other sources read them.
	StaleAccountDays     int  `mapstructure:"stale_account_days"`
	MaxUsers             int  `mapstructure:"max_users"`
	MaxServicePrincipals int  `mapstructure:"max_service_principals"`
	MaxGroups            int  `mapstructure:"max_groups"`
	MaxDevices           int  `mapstructure:"max_devices"`
	Enabled              bool `mapstructure:"enabled"`
	CollectSoftware      bool `mapstructure:"collect_software"`
	CollectInterfaces    bool `mapstructure:"collect_interfaces"`
	TLSSkipVerify        bool `mapstructure:"tls_skip_verify"`
	CollectUsers         bool `mapstructure:"collect_users"`
	CollectGroups        bool `mapstructure:"collect_groups"`
	CollectOUs           bool `mapstructure:"collect_ous"`
	CollectGPOs          bool `mapstructure:"collect_gpos"`
}

// ClassificationConfig holds authorization and managed-status classification settings.
type ClassificationConfig struct {
	Authorization AuthorizationConfig `mapstructure:"authorization"`
	Managed       ManagedConfig       `mapstructure:"managed"`
}

// AuthorizationConfig controls how assets are matched against an allowlist.
type AuthorizationConfig struct {
	AllowlistFile string   `mapstructure:"allowlist_file"`
	MatchFields   []string `mapstructure:"match_fields"`
}

// ManagedConfig defines which controls must be present for an asset to be
// considered "managed".
type ManagedConfig struct {
	RequiredControls []string `mapstructure:"required_controls"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Listen  string `mapstructure:"listen"`
	Enabled bool   `mapstructure:"enabled"`
}

// StreamingConfig configures the continuous streaming agent mode.
type StreamingConfig struct {
	Interval string     `mapstructure:"interval"` // duration string like "6h"
	OTLP     OTLPConfig `mapstructure:"otlp"`
}

// OTLPConfig configures the OTLP event emitter.
type OTLPConfig struct {
	Endpoint string    `mapstructure:"endpoint"`
	Protocol string    `mapstructure:"protocol"` // "grpc" or "http"
	TLS      TLSConfig `mapstructure:"tls"`
}

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
	Enabled  bool   `mapstructure:"enabled"`
}

// AuditConfig configures the configuration audit subsystem.
type AuditConfig struct {
	Profile           string                       `mapstructure:"profile"`
	SCA               SCAAuditConfig               `mapstructure:"sca"`
	SSH               SSHAuditConfig               `mapstructure:"ssh"`
	Service           ServiceAuditConfig           `mapstructure:"service"`
	EnvSecrets        EnvSecretsAuditConfig        `mapstructure:"env_secrets"`
	Permissions       PermissionsAuditConfig       `mapstructure:"permissions"`
	ProcessEnvSecrets ProcessEnvSecretsAuditConfig `mapstructure:"process_env_secrets"`
	Firewall          AuditorToggle                `mapstructure:"firewall"`
	Kernel            AuditorToggle                `mapstructure:"kernel"`
	Secrets           AuditorToggle                `mapstructure:"secrets"`
	LDAP              AuditorToggle                `mapstructure:"ldap"`
	Entra             AuditorToggle                `mapstructure:"entra"`
	Enabled           bool                         `mapstructure:"enabled"`
}

// EnvSecretsAuditConfig configures the container env secret scanner
// (RFC-0123). DenyList is a list of env var name prefixes (case-insensitive)
// to exclude from scanning. The scanner is opt-in.
type EnvSecretsAuditConfig struct {
	DenyList []string `mapstructure:"deny_list"`
	Enabled  bool     `mapstructure:"enabled"`
}

// ProcessEnvSecretsAuditConfig configures the host process env secret
// scanner (RFC-0123). ProcessFilter restricts scanning to processes whose
// name (from /proc/<pid>/comm) appears in the list; an empty filter
// scans every readable process. MaxPIDs caps the number of PIDs scanned;
// 0 uses the auditor default (10,000). The scanner is opt-in.
type ProcessEnvSecretsAuditConfig struct {
	ProcessFilter []string `mapstructure:"process_filter"`
	DenyList      []string `mapstructure:"deny_list"`
	MaxPIDs       int      `mapstructure:"max_pids"`
	Enabled       bool     `mapstructure:"enabled"`
}

// SCAAuditConfig configures the Software Composition Analysis auditor.
type SCAAuditConfig struct {
	Timeout string `mapstructure:"timeout"` // OSV API request timeout, e.g. "30s"
	Enabled bool   `mapstructure:"enabled"`
}

// ParseTimeout parses the Timeout duration string. Falls back to 30s.
func (s *SCAAuditConfig) ParseTimeout() time.Duration {
	if s.Timeout == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// AuditorToggle is a simple enabled/disabled toggle for an auditor.
type AuditorToggle struct {
	Enabled bool `mapstructure:"enabled"`
}

// SSHAuditConfig configures the SSH auditor.
type SSHAuditConfig struct {
	ConfigPath string `mapstructure:"config_path"`
	Enabled    bool   `mapstructure:"enabled"`
}

// PermissionsAuditConfig configures the permissions auditor.
type PermissionsAuditConfig struct {
	Paths   []string `mapstructure:"paths"`
	Enabled bool     `mapstructure:"enabled"`
}

// ServiceAuditConfig configures the service auditor.
type ServiceAuditConfig struct {
	CriticalPorts []int `mapstructure:"critical_ports"`
	Enabled       bool  `mapstructure:"enabled"`
}

// PostureConfig configures the posture analysis engine.
type PostureConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// PostgresConfig configures the PostgreSQL backend for streaming mode.
type PostgresConfig struct {
	DSN string `mapstructure:"dsn"`
}

// Load reads configuration from a YAML file at path, applies defaults, and
// binds environment variables with the "KITE" prefix.  Environment variables
// use underscores as separators (e.g. KITE_LOG_LEVEL).
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("log_level", "info")
	v.SetDefault("output_format", "table")
	v.SetDefault("data_dir", ".")
	v.SetDefault("stale_threshold", "168h")
	v.SetDefault("discovery.sources.agent.enabled", true)
	v.SetDefault("discovery.sources.agent.collect_software", true)
	v.SetDefault("discovery.sources.agent.collect_interfaces", true)
	v.SetDefault("metrics.enabled", false)
	v.SetDefault("metrics.listen", ":9090")
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.profile", "standard")
	v.SetDefault("audit.ssh.enabled", true)
	v.SetDefault("audit.ssh.config_path", "/etc/ssh/sshd_config")
	v.SetDefault("audit.firewall.enabled", true)
	v.SetDefault("audit.kernel.enabled", true)
	v.SetDefault("audit.permissions.enabled", true)
	v.SetDefault("audit.service.enabled", true)
	v.SetDefault("audit.service.critical_ports", []int{23, 21, 111, 3306, 5432, 6379, 9200})
	v.SetDefault("audit.entra.enabled", true)
	v.SetDefault("audit.env_secrets.enabled", false)
	v.SetDefault("audit.process_env_secrets.enabled", false)
	v.SetDefault("audit.process_env_secrets.max_pids", 10000)
	v.SetDefault("posture.enabled", true)
	v.SetDefault("streaming.interval", "6h")
	v.SetDefault("streaming.otlp.endpoint", "https://otel.vulnertrack.io")
	v.SetDefault("streaming.otlp.protocol", "grpc")
	v.SetDefault("safety.scan_deadline", "30m")
	v.SetDefault("safety.max_response_bytes", 10485760) // 10 MB
	v.SetDefault("safety.max_request_bytes", 1048576)   // 1 MB
	v.SetDefault("safety.circuit_breaker.failure_threshold", 3)
	v.SetDefault("safety.circuit_breaker.cooldown", "5m")
	v.SetDefault("safety.circuit_breaker.success_threshold", 1)
	v.SetDefault("identity.data_dir", "/var/lib/kite-collector")
	v.SetDefault("identity.key_backend", "auto")
	v.SetDefault("connectivity.tunnel.enabled", false)
	v.SetDefault("connectivity.tunnel.provider", "")
	v.SetDefault("connectivity.tunnel.target", "")
	v.SetDefault("connectivity.tunnel.local_port", 14318)
	v.SetDefault("connectivity.tunnel.auth_token_env", "KITE_TUNNEL_AUTH_TOKEN")
	v.SetDefault("connectivity.tunnel.restart_max", 5)
	v.SetDefault("connectivity.tunnel.restart_backoff_base", "5s")
	v.SetDefault("connectivity.tunnel.restart_backoff_max", "5m")
	v.SetDefault("fleet.enabled", false)
	v.SetDefault("fleet.require_enrollment", false)
	v.SetDefault("fleet.mtls_required", false)

	// Environment variable binding
	v.SetEnvPrefix("KITE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file when a path is provided
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

// Validate checks configuration values for common errors and returns a
// descriptive error for the first problem found.
func (c *Config) Validate() error {
	// Stale threshold must be parseable.
	if c.StaleThreshold != "" {
		if _, err := time.ParseDuration(c.StaleThreshold); err != nil {
			return fmt.Errorf("invalid stale_threshold %q: %w", c.StaleThreshold, err)
		}
	}

	// Log level must be recognized.
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "error":
		// ok
	default:
		return fmt.Errorf("invalid log_level %q: expected debug, info, warn, or error", c.LogLevel)
	}

	// Validate CIDR scopes in network source.
	if netSrc, ok := c.Discovery.Sources["network"]; ok && netSrc.Enabled {
		for _, cidr := range netSrc.Scope {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("invalid CIDR in network scope %q: %w", cidr, err)
			}
		}
	}

	// Streaming interval must be parseable when set.
	if c.Streaming.Interval != "" {
		if _, err := time.ParseDuration(c.Streaming.Interval); err != nil {
			return fmt.Errorf("invalid streaming interval %q: %w", c.Streaming.Interval, err)
		}
	}

	// Allowlist file must exist if configured.
	if p := c.Classification.Authorization.AllowlistFile; p != "" {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("allowlist_file %q: %w", p, err)
		}
	}

	// Validate endpoints.
	names := make(map[string]struct{})
	for i, ep := range c.Endpoints {
		if ep.Name == "" {
			return fmt.Errorf("endpoints[%d]: name is required", i)
		}
		if _, dup := names[ep.Name]; dup {
			return fmt.Errorf("endpoints[%d]: duplicate name %q", i, ep.Name)
		}
		names[ep.Name] = struct{}{}
		if ep.Address == "" {
			return fmt.Errorf("endpoints[%d] %q: address is required", i, ep.Name)
		}
		if ep.Health.Interval != "" {
			if _, err := time.ParseDuration(ep.Health.Interval); err != nil {
				return fmt.Errorf("endpoints[%d] %q: invalid health interval: %w", i, ep.Name, err)
			}
		}
		if ep.Health.Timeout != "" {
			if _, err := time.ParseDuration(ep.Health.Timeout); err != nil {
				return fmt.Errorf("endpoints[%d] %q: invalid health timeout: %w", i, ep.Name, err)
			}
		}
	}

	// Validate identity key backend.
	switch c.Identity.KeyBackend {
	case "", "auto", "tpm", "keyring", "file":
		// ok
	default:
		return fmt.Errorf("invalid identity.key_backend %q: expected auto, tpm, keyring, or file", c.Identity.KeyBackend)
	}

	// Validate tunnel config when enabled.
	if c.Connectivity.Tunnel.Enabled {
		t := c.Connectivity.Tunnel
		switch t.Provider {
		case "ngrok", "cloudflared", "bore", "tailscale", "frp", "rathole":
			// ok
		case "":
			return fmt.Errorf("connectivity.tunnel.provider is required when tunnel is enabled")
		default:
			return fmt.Errorf("invalid connectivity.tunnel.provider %q: expected ngrok, cloudflared, bore, tailscale, frp, or rathole", t.Provider)
		}
		if t.Target == "" {
			return fmt.Errorf("connectivity.tunnel.target is required when tunnel is enabled")
		}
		if t.LocalPort < 1 || t.LocalPort > 65535 {
			return fmt.Errorf("connectivity.tunnel.local_port must be 1-65535, got %d", t.LocalPort)
		}
		if t.BackoffBase != "" {
			if _, err := time.ParseDuration(t.BackoffBase); err != nil {
				return fmt.Errorf("invalid connectivity.tunnel.restart_backoff_base %q: %w", t.BackoffBase, err)
			}
		}
		if t.BackoffMax != "" {
			if _, err := time.ParseDuration(t.BackoffMax); err != nil {
				return fmt.Errorf("invalid connectivity.tunnel.restart_backoff_max %q: %w", t.BackoffMax, err)
			}
		}
	}

	// Validate fleet config: tenant_id must be a valid UUID if set.
	if c.Fleet.TenantID != "" {
		if len(c.Fleet.TenantID) != 36 {
			return fmt.Errorf("invalid fleet.tenant_id %q: expected UUID format", c.Fleet.TenantID)
		}
	}

	return nil
}

// StaleThresholdDuration parses the StaleThreshold string into a
// time.Duration.  If the string is empty or invalid, it falls back to 168h
// (7 days).
func (c *Config) StaleThresholdDuration() time.Duration {
	if c.StaleThreshold == "" {
		return 168 * time.Hour
	}
	d, err := time.ParseDuration(c.StaleThreshold)
	if err != nil {
		return 168 * time.Hour
	}
	return d
}

// StreamingInterval parses the Streaming.Interval string into a
// time.Duration. Falls back to 6h if empty or invalid.
func (c *Config) StreamingInterval() time.Duration {
	if c.Streaming.Interval == "" {
		return 6 * time.Hour
	}
	d, err := time.ParseDuration(c.Streaming.Interval)
	if err != nil {
		return 6 * time.Hour
	}
	return d
}

// IsSourceEnabled reports whether the named discovery source exists in the
// configuration and has Enabled set to true.
func (c *Config) IsSourceEnabled(name string) bool {
	src, ok := c.Discovery.Sources[name]
	if !ok {
		return false
	}
	return src.Enabled
}

// SourceCfg returns the SourceConfig for the given source name.  If the
// source does not exist, a zero-value SourceConfig is returned.
func (c *Config) SourceCfg(name string) SourceConfig {
	return c.Discovery.Sources[name]
}
