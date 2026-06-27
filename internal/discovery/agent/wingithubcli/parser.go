package wingithubcli

import (
	"gopkg.in/yaml.v3"
)

// hostsDoc mirrors the top-level shape of `gh`'s hosts.yml:
//
//	github.com:
//	    user: alice
//	    oauth_token: ghp_xxxxxxxxxxxxxxx
//	    git_protocol: ssh
//	github.example.com:
//	    user: bob
//	    oauth_token: ghu_yyyyyyyyyyyyyy
//	    git_protocol: https
type hostsDoc map[string]hostBlock

type hostBlock struct {
	User        string `yaml:"user"`
	OauthToken  string `yaml:"oauth_token"`
	GitProtocol string `yaml:"git_protocol"`
}

// ParseHostsYAML emits one Row per host stanza. Tokens are
// replaced by their 4-char family prefix (never persisted
// verbatim). Malformed or empty docs return [].
func ParseHostsYAML(body []byte) []Row {
	out := make([]Row, 0, 2)
	if len(body) == 0 {
		return out
	}
	var doc hostsDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return out
	}
	for host, block := range doc {
		if host == "" {
			continue
		}
		r := Row{
			Host:        host,
			GhUser:      block.User,
			GitProtocol: block.GitProtocol,
		}
		if block.OauthToken != "" {
			r.IsOAuthTokenPresent = true
			r.TokenFamily = TokenFamilyPrefix(block.OauthToken)
		}
		out = append(out, r)
		if len(out) >= MaxRows {
			return out
		}
	}
	return out
}
