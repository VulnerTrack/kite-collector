package mongodconf

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// rawConfig mirrors only the sections of mongod.conf we care about
// for security findings. yaml.v3 ignores keys without struct tags,
// so unknown extras (storage.wiredTiger.*, processManagement.*, etc.)
// flow past without error.
type rawConfig struct {
	SetParameter map[string]any `yaml:"setParameter,omitempty"`
	Security     struct {
		Authorization     string `yaml:"authorization,omitempty"`
		JavascriptEnabled *bool  `yaml:"javascriptEnabled,omitempty"`
		ClusterAuthMode   string `yaml:"clusterAuthMode,omitempty"`
		KeyFile           string `yaml:"keyFile,omitempty"`
	} `yaml:"security,omitempty"`
	SystemLog struct {
		Destination string `yaml:"destination,omitempty"`
		Path        string `yaml:"path,omitempty"`
	} `yaml:"systemLog,omitempty"`
	Storage struct {
		DBPath string `yaml:"dbPath,omitempty"`
	} `yaml:"storage,omitempty"`
	Replication struct {
		ReplSetName string `yaml:"replSetName,omitempty"`
	} `yaml:"replication,omitempty"`
	Net struct {
		BindIPAll *bool `yaml:"bindIpAll,omitempty"`
		HTTP      struct {
			Enabled *bool `yaml:"enabled,omitempty"`
		} `yaml:"http,omitempty"`
		TLS struct {
			Mode               string `yaml:"mode,omitempty"`
			CertificateKeyFile string `yaml:"certificateKeyFile,omitempty"`
			CAFile             string `yaml:"CAFile,omitempty"`
		} `yaml:"tls,omitempty"`
		BindIP     string   `yaml:"bindIp,omitempty"`
		BindIPList []string `yaml:"-"`
		Port       int      `yaml:"port,omitempty"`
	} `yaml:"net,omitempty"`
}

// ParseConfig walks a mongod.conf YAML body and returns a populated
// State (without `Source` set — the collector tags it). Empty body
// returns an error so the caller can distinguish "no probe ran"
// from "the daemon is using compiled-in defaults".
func ParseConfig(body []byte) (State, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return State{}, errors.New("empty mongod.conf")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawConfig
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return State{}, fmt.Errorf("yaml unmarshal: %w", err)
	}

	out := State{
		Port:              raw.Net.Port,
		BindIPs:           splitBindIP(raw.Net.BindIP),
		TLSMode:           strings.TrimSpace(raw.Net.TLS.Mode),
		TLSCertKeyFile:    strings.TrimSpace(raw.Net.TLS.CertificateKeyFile),
		TLSCAFile:         strings.TrimSpace(raw.Net.TLS.CAFile),
		DBPath:            strings.TrimSpace(raw.Storage.DBPath),
		LogPath:           strings.TrimSpace(raw.SystemLog.Path),
		LogDestination:    strings.TrimSpace(raw.SystemLog.Destination),
		AuthorizationMode: strings.ToLower(strings.TrimSpace(raw.Security.Authorization)),
		ClusterAuthMode:   strings.TrimSpace(raw.Security.ClusterAuthMode),
		KeyfilePath:       strings.TrimSpace(raw.Security.KeyFile),
		ReplicaSetName:    strings.TrimSpace(raw.Replication.ReplSetName),
	}

	// `net.bindIpAll: true` overrides bindIp.
	if raw.Net.BindIPAll != nil && *raw.Net.BindIPAll {
		out.BindIPs = []string{"0.0.0.0"}
	}

	// Default behaviour per the docs: when `security.authorization`
	// is absent, mongod treats it as disabled.
	if out.AuthorizationMode == "" || out.AuthorizationMode == "disabled" {
		out.IsAuthorizationDisabled = true
	}

	// Server-side scripting: default = enabled per the manual.
	if raw.Security.JavascriptEnabled == nil {
		out.IsScriptingEnabled = true
	} else {
		out.IsScriptingEnabled = *raw.Security.JavascriptEnabled
	}

	// Legacy HTTP interface — removed in 3.6 but configs from earlier
	// versions still surface in the wild.
	if raw.Net.HTTP.Enabled != nil {
		out.IsHTTPInterfaceEnabled = *raw.Net.HTTP.Enabled
	}

	// setParameter is a free-form map. The two security-relevant keys
	// surface as derived booleans.
	if raw.SetParameter != nil {
		if v, ok := raw.SetParameter["enableLocalhostAuthBypass"]; ok {
			out.IsLocalhostAuthBypassEnabled = boolFromAny(v, true)
		}
	}

	return out, nil
}

// splitBindIP tokenises `net.bindIp` which is a comma-separated list
// (per the mongod.conf docs). Whitespace tolerance is intentional —
// most operators write `127.0.0.1, ::1`.
func splitBindIP(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// boolFromAny coerces a YAML scalar into Go bool. Strings are
// interpreted permissively — `"true"` / `"yes"` / `"on"` / `"1"` →
// true.
func boolFromAny(v any, def bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		switch s {
		case "true", "yes", "on", "1":
			return true
		case "false", "no", "off", "0":
			return false
		}
		return def
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	}
	return def
}
