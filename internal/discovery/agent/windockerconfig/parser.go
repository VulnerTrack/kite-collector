package windockerconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// rawConfig mirrors the subset of Docker CLI config.json we
// inventory. Unknown keys flow past via the json decoder.
type rawConfig struct {
	Proxies             rawProxies         `json:"proxies"`
	Auths               map[string]rawAuth `json:"auths"`
	CredHelpers         map[string]string  `json:"credHelpers"`
	CredsStore          string             `json:"credsStore"`
	Experimental        string             `json:"experimental"`
	CLIPluginsExtraDirs []string           `json:"cliPluginsExtraDirs"`
}

type rawAuth struct {
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
	Email         string `json:"email"`
}

type rawProxies struct {
	PerEndpoint map[string]rawProxyEntry `json:"-"`
	Default     rawProxyEntry            `json:"default"`
}

type rawProxyEntry struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
	FTPProxy   string `json:"ftpProxy"`
}

// ParseConfig walks one Docker CLI config.json body and emits
// one Entry per discovered registry-auth / cred-helper / proxy /
// plugin-dir / cli-config row. The collector stamps file-level
// metadata (FilePath/FileHash/FileMode/FileOwnerUID/UserProfile)
// on every row.
func ParseConfig(body []byte) ([]Entry, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty docker config")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawConfig
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal docker config: %w", err)
	}

	out := make([]Entry, 0, len(raw.Auths)+len(raw.CredHelpers)+4)

	// auths.<registry>
	for _, name := range sortedKeys(authKeys(raw.Auths)) {
		a := raw.Auths[name]
		out = append(out, Entry{
			EntryKind:        EntryAuth,
			EntryName:        name,
			RegistryHost:     extractRegistryHost(name),
			HasInlineAuth:    strings.TrimSpace(a.Auth) != "",
			HasIdentityToken: strings.TrimSpace(a.IdentityToken) != "",
		})
	}

	// credsStore (global) — if set without credHelpers, the global
	// helper applies to every registry. We surface a single row.
	if global := strings.TrimSpace(raw.CredsStore); global != "" {
		out = append(out, Entry{
			EntryKind:            EntryCredHelper,
			EntryName:            "<global>",
			CredentialHelperName: global,
		})
	}
	// credHelpers.<registry> — per-registry helper override.
	for _, name := range sortedKeys(stringMapKeys(raw.CredHelpers)) {
		out = append(out, Entry{
			EntryKind:            EntryCredHelper,
			EntryName:            name,
			RegistryHost:         extractRegistryHost(name),
			CredentialHelperName: raw.CredHelpers[name],
		})
	}

	// proxies.default — surface httpProxy + httpsProxy + ftpProxy
	// as separate rows so the audit pipeline can alert on each.
	for _, kv := range []struct {
		key string
		val string
	}{
		{"default.httpProxy", raw.Proxies.Default.HTTPProxy},
		{"default.httpsProxy", raw.Proxies.Default.HTTPSProxy},
		{"default.ftpProxy", raw.Proxies.Default.FTPProxy},
	} {
		if strings.TrimSpace(kv.val) == "" {
			continue
		}
		out = append(out, Entry{
			EntryKind: EntryProxy,
			EntryName: kv.key,
			ProxyURL:  kv.val,
		})
	}

	// cliPluginsExtraDirs — each is a search-path entry.
	for _, dir := range raw.CLIPluginsExtraDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		out = append(out, Entry{
			EntryKind:    EntryCLIPluginDir,
			EntryName:    dir,
			CLIPluginDir: dir,
		})
	}

	// Experimental flag → a single cli-config row.
	if v := strings.TrimSpace(raw.Experimental); v != "" {
		out = append(out, Entry{
			EntryKind: EntryCLIConfig,
			EntryName: "experimental=" + v,
		})
	}

	return out, nil
}

func authKeys(m map[string]rawAuth) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stringMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys(keys []string) []string {
	sort.Strings(keys)
	return keys
}

// extractRegistryHost strips the optional scheme + path from a
// registry key (Docker auths key may be `https://index.docker.io/v1/`).
func extractRegistryHost(key string) string {
	v := strings.TrimSpace(key)
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?"); i >= 0 {
		v = v[:i]
	}
	return v
}
