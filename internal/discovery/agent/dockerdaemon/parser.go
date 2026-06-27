package dockerdaemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// rawConfig is the on-disk daemon.json shape. Every field is
// optional — Docker fills defaults from dockerd. We only mirror the
// ones with security signal; everything else is dropped.
type rawConfig struct {
	NoNewPrivileges    *bool           `json:"no-new-privileges,omitempty"`
	TLSVerify          *bool           `json:"tlsverify,omitempty"`
	Experimental       *bool           `json:"experimental,omitempty"`
	SELinuxEnabled     *bool           `json:"selinux-enabled,omitempty"`
	LiveRestore        *bool           `json:"live-restore,omitempty"`
	Iptables           *bool           `json:"iptables,omitempty"`
	TLS                *bool           `json:"tls,omitempty"`
	TLSCert            string          `json:"tlscert,omitempty"`
	TLSCACert          string          `json:"tlscacert,omitempty"`
	UsernsRemap        string          `json:"userns-remap,omitempty"`
	LogDriver          string          `json:"log-driver,omitempty"`
	SeccompProfile     string          `json:"seccomp-profile,omitempty"`
	TLSKey             string          `json:"tlskey,omitempty"`
	StorageDriver      string          `json:"storage-driver,omitempty"`
	CgroupParent       string          `json:"cgroup-parent,omitempty"`
	DefaultRuntime     string          `json:"default-runtime,omitempty"`
	DefaultUlimits     json.RawMessage `json:"default-ulimits,omitempty"`
	InsecureRegistries []string        `json:"insecure-registries,omitempty"`
	Hosts              []string        `json:"hosts,omitempty"`
	RegistryMirrors    []string        `json:"registry-mirrors,omitempty"`
}

// ParseDaemonJSON walks a daemon.json body and returns a State with
// every security-relevant field populated. Empty body → an empty
// State (caller's responsibility to set Source).
func ParseDaemonJSON(body []byte) (State, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return State{}, errors.New("empty daemon.json")
	}
	// Tolerate UTF-8 BOM and shell-style comments? daemon.json is
	// strict JSON per moby; we don't try to be more permissive.
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawConfig
	if err := json.Unmarshal(body, &raw); err != nil {
		return State{}, fmt.Errorf("unmarshal daemon.json: %w", err)
	}

	out := State{
		Hosts:              dedupeNonEmpty(raw.Hosts),
		InsecureRegistries: dedupeNonEmpty(raw.InsecureRegistries),
		RegistryMirrors:    dedupeNonEmpty(raw.RegistryMirrors),
		DefaultRuntime:     strings.TrimSpace(raw.DefaultRuntime),
		CgroupParent:       strings.TrimSpace(raw.CgroupParent),
		StorageDriver:      strings.TrimSpace(raw.StorageDriver),
		LogDriver:          strings.TrimSpace(raw.LogDriver),
		UsernsRemap:        strings.TrimSpace(raw.UsernsRemap),
		SeccompProfile:     strings.TrimSpace(raw.SeccompProfile),
		IsTLSEnabled:       boolDefault(raw.TLS, false) || boolDefault(raw.TLSVerify, false) || raw.TLSCert != "",
		IsTLSVerifyEnabled: boolDefault(raw.TLSVerify, false),
		// Defaults per dockerd(8) when the key is absent:
		//   iptables=true, live-restore=false, selinux-enabled=false,
		//   experimental=false, no-new-privileges=false.
		IsNoNewPrivilegesDefault: boolDefault(raw.NoNewPrivileges, false),
		IsIptablesManaged:        boolDefault(raw.Iptables, true),
		IsLiveRestoreEnabled:     boolDefault(raw.LiveRestore, false),
		IsSELinuxEnabled:         boolDefault(raw.SELinuxEnabled, false),
		IsExperimentalEnabled:    boolDefault(raw.Experimental, false),
	}
	return out, nil
}

func boolDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func dedupeNonEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
