package cloudcreds

import "context"

// Stubs for credential surfaces not yet wired. Each returns empty so
// the multi-provider chain runs unconditionally.

// NewAzureCollector returns a stub Azure CLI credential collector.
//
// TODO(cdms-iter): parse ~/.azure/azureProfile.json (list of
// subscriptions + tenant IDs — non-secret) and
// ~/.azure/msal_token_cache.bin (presence flag only — opaque blob,
// never read). The token cache is encrypted with the user's DPAPI key
// on Windows or libsecret on Linux, so even reading it is gated.
func NewAzureCollector() Collector { return sourceStub{name: "azure-stub"} }

// NewGitHubCollector returns a stub GitHub CLI / token-file collector.
//
// TODO(cdms-iter): ~/.config/gh/hosts.yml (gh CLI) and ~/.config/gh/
// gist.yml. Token rows in the host_cloud_credentials table get
// provider='github', credential_type='bearer-token'. Also scan for
// ~/.git-credentials, ~/.netrc (machine github.com entries).
func NewGitHubCollector() Collector { return sourceStub{name: "github-stub"} }

// NewDockerCollector returns a stub Docker registry credential collector.
//
// TODO(cdms-iter): ~/.docker/config.json contains an "auths" map of
// registry-URL → base64(user:pass). We extract registry URLs +
// auth-type, never the credential payload. On Linux the secret may
// instead live in `credsStore` (libsecret/pass/etc.) which means we
// only see the storage backend name.
func NewDockerCollector() Collector { return sourceStub{name: "docker-stub"} }

// NewNPMCollector returns a stub npm / yarn token collector.
//
// TODO(cdms-iter): ~/.npmrc and project-local .npmrc files contain
// `//registry.npmjs.org/:_authToken=…`. We extract the registry host
// and flag token presence, never the value.
func NewNPMCollector() Collector { return sourceStub{name: "npm-stub"} }

// NewTerraformCloudCollector returns a stub Terraform Cloud collector.
//
// TODO(cdms-iter): ~/.terraform.d/credentials.tfrc.json. Format:
//
//	{"credentials":{"app.terraform.io":{"token":"…"}}}
//
// One row per host URL, type='api-key', flag token presence.
func NewTerraformCloudCollector() Collector { return sourceStub{name: "tfc-stub"} }

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Credential, error) {
	return []Credential{}, nil
}
