package winkubeconfig

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// rawConfig mirrors the subset of the kubeconfig schema we
// inventory. yaml.v3 unmarshals omitted fields to their zero
// value so we don't need to worry about optional keys.
type rawConfig struct {
	CurrentContext string       `yaml:"current-context"`
	Clusters       []rawCluster `yaml:"clusters"`
	Users          []rawUser    `yaml:"users"`
	Contexts       []rawContext `yaml:"contexts"`
}

type rawCluster struct {
	Name    string         `yaml:"name"`
	Cluster rawClusterSpec `yaml:"cluster"`
}

type rawClusterSpec struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
}

type rawUser struct {
	Name string      `yaml:"name"`
	User rawUserSpec `yaml:"user"`
}

type rawUserSpec struct {
	Token                 string          `yaml:"token"`
	TokenFile             string          `yaml:"tokenFile"`
	ClientCertificate     string          `yaml:"client-certificate"`
	ClientCertificateData string          `yaml:"client-certificate-data"`
	ClientKey             string          `yaml:"client-key"`
	ClientKeyData         string          `yaml:"client-key-data"`
	Username              string          `yaml:"username"`
	Password              string          `yaml:"password"`
	AuthProvider          rawAuthProvider `yaml:"auth-provider"`
	Exec                  rawExec         `yaml:"exec"`
}

type rawAuthProvider struct {
	Config map[string]string `yaml:"config"`
	Name   string            `yaml:"name"`
}

type rawExec struct {
	APIVersion string       `yaml:"apiVersion"`
	Command    string       `yaml:"command"`
	Args       []string     `yaml:"args"`
	Env        []rawExecEnv `yaml:"env"`
}

type rawExecEnv struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type rawContext struct {
	Name    string         `yaml:"name"`
	Context rawContextSpec `yaml:"context"`
}

type rawContextSpec struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace"`
}

// ParseKubeconfig walks one kubeconfig YAML body and returns
// one Entry per cluster/user/context. The collector stamps
// file-level metadata (FilePath/FileHash/FileMode/FileOwnerUID/
// UserProfile) on every row.
func ParseKubeconfig(body []byte) ([]Entry, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty kubeconfig")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var raw rawConfig
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal kubeconfig: %w", err)
	}

	out := make([]Entry, 0, len(raw.Clusters)+len(raw.Users)+len(raw.Contexts))
	for _, c := range raw.Clusters {
		e := Entry{
			EntryKind: EntryCluster,
			EntryName: strings.TrimSpace(c.Name),
			Server:    strings.TrimSpace(c.Cluster.Server),
			HasCertificateAuthority: strings.TrimSpace(c.Cluster.CertificateAuthority) != "" ||
				strings.TrimSpace(c.Cluster.CertificateAuthorityData) != "",
			IsInsecureSkipTLSVerify: c.Cluster.InsecureSkipTLSVerify,
		}
		out = append(out, e)
	}
	for _, u := range raw.Users {
		e := Entry{
			EntryKind: EntryUser,
			EntryName: strings.TrimSpace(u.Name),
		}
		fillUser(&e, u.User)
		out = append(out, e)
	}
	for _, c := range raw.Contexts {
		e := Entry{
			EntryKind:        EntryContext,
			EntryName:        strings.TrimSpace(c.Name),
			ContextCluster:   strings.TrimSpace(c.Context.Cluster),
			ContextUser:      strings.TrimSpace(c.Context.User),
			ContextNamespace: strings.TrimSpace(c.Context.Namespace),
			IsCurrentContext: strings.TrimSpace(c.Name) != "" &&
				c.Name == raw.CurrentContext,
		}
		out = append(out, e)
	}
	return out, nil
}

// fillUser populates the auth-kind, exec, and inline-credential
// fields on a user Entry from the rawUserSpec.
func fillUser(e *Entry, u rawUserSpec) {
	e.HasInlineToken = strings.TrimSpace(u.Token) != ""
	e.HasInlineCertificate = strings.TrimSpace(u.ClientCertificateData) != "" ||
		strings.TrimSpace(u.ClientCertificate) != ""
	e.HasBasicAuth = strings.TrimSpace(u.Username) != "" &&
		strings.TrimSpace(u.Password) != ""
	e.HasExecPlugin = strings.TrimSpace(u.Exec.Command) != ""
	if e.HasExecPlugin {
		e.ExecCommand = strings.TrimSpace(u.Exec.Command)
	}
	if name := strings.TrimSpace(u.AuthProvider.Name); name != "" {
		e.AuthProviderName = name
	}

	switch {
	case e.HasInlineToken || strings.TrimSpace(u.TokenFile) != "":
		e.AuthKind = AuthToken
	case e.HasExecPlugin:
		e.AuthKind = AuthExec
	case e.AuthProviderName != "":
		e.AuthKind = AuthAuthProvider
	case e.HasInlineCertificate:
		e.AuthKind = AuthCert
	case e.HasBasicAuth:
		e.AuthKind = AuthBasic
	default:
		e.AuthKind = AuthNone
	}
}
