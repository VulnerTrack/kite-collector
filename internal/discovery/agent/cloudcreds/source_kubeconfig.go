package cloudcreds

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// kubeconfigCollector parses ~/.kube/config (and KUBECONFIG-multi).
// Kubeconfig YAML has three top-level lists — clusters, users, contexts
// — joined by `current-context`. Each context is one row in our table,
// flagging the credential type from the underlying user entry:
//
//	user:
//	  token: bearer-token-here          → CredBearerToken
//	  username: alice                   → CredBasicAuth
//	  password: pw
//	  client-certificate-data: <base64> → CredAccessKey (mTLS-style)
//	  exec: {command: aws, args: [...]} → CredOAuthAccess (federated)
//
// We never decode the base64 cert/key data, and we never read the
// token / password values — we only flag their presence.
type kubeconfigCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	homeRoots []string
}

// NewKubeconfigCollector returns the default ~/.kube/config walker.
func NewKubeconfigCollector() Collector {
	return &kubeconfigCollector{
		homeRoots: defaultHomeRoots(),
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME path
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *kubeconfigCollector) Name() string { return "kubeconfig-files" }

func (c *kubeconfigCollector) Collect(ctx context.Context) ([]Credential, error) {
	var out []Credential
	for _, home := range walkHomes(c.readDir, c.homeRoots) {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		user := filepath.Base(home)
		path := filepath.Join(home, ".kube", "config")
		out = append(out, c.parseKubeconfig(path, user)...)
		if len(out) >= MaxCredentials {
			SortCredentials(out)
			return out[:MaxCredentials], nil
		}
	}
	SortCredentials(out)
	return out, nil
}

// kubeconfigYAML mirrors only the fields we care about. We deliberately
// model the credential-bearing fields as bool-able pointers / opaque
// strings so json/yaml.Unmarshal doesn't allocate buffers for the
// secrets — but YAML unmarshalling doesn't have json.RawMessage's
// "leave it alone" semantic, so we just declare the secret fields as
// `string` and wipe after extraction.
type kubeconfigYAML struct {
	Kind           string                `yaml:"kind"`
	CurrentContext string                `yaml:"current-context"`
	Clusters       []kubeconfigCluster   `yaml:"clusters"`
	Users          []kubeconfigUserEntry `yaml:"users"`
	Contexts       []kubeconfigContext   `yaml:"contexts"`
}

type kubeconfigCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server               string `yaml:"server"`
		CertificateAuthority string `yaml:"certificate-authority,omitempty"`
	} `yaml:"cluster"`
}

type kubeconfigUserEntry struct {
	User kubeconfigUser `yaml:"user"`
	Name string         `yaml:"name"`
}

type kubeconfigUser struct {
	Exec                  *kubeconfigExec `yaml:"exec,omitempty"`
	AuthProvider          map[string]any  `yaml:"auth-provider,omitempty"`
	Token                 string          `yaml:"token,omitempty"`
	TokenFile             string          `yaml:"tokenFile,omitempty"`
	Username              string          `yaml:"username,omitempty"`
	Password              string          `yaml:"password,omitempty"`
	ClientCertificateData string          `yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string          `yaml:"client-key-data,omitempty"`
}

type kubeconfigExec struct {
	Command string `yaml:"command"`
}

type kubeconfigContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	} `yaml:"context"`
}

// parseKubeconfig builds one Credential per (cluster, user, context)
// tuple. Defers to the cred-type classifier on what kind of credential
// the user entry holds.
func (c *kubeconfigCollector) parseKubeconfig(path, owner string) []Credential {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	defer wipe(data)

	var doc kubeconfigYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if doc.Kind != "" && doc.Kind != "Config" {
		return nil
	}

	clusters := make(map[string]kubeconfigCluster, len(doc.Clusters))
	for _, c := range doc.Clusters {
		clusters[c.Name] = c
	}
	users := make(map[string]kubeconfigUser, len(doc.Users))
	for _, u := range doc.Users {
		users[u.Name] = u.User
	}

	out := make([]Credential, 0, len(doc.Contexts))
	for _, ctx := range doc.Contexts {
		clus := clusters[ctx.Context.Cluster]
		usr := users[ctx.Context.User]
		credType, longLived, federated := classifyKubeconfigUser(usr)

		out = append(out, Credential{
			Provider:            ProviderKubeconfig,
			CredentialType:      credType,
			Profile:             ctx.Name,
			OwnerUser:           owner,
			AccountID:           clus.Cluster.Server, // cluster API URL = the "account"
			SessionTokenPresent: usr.Token != "" || usr.TokenFile != "",
			IsLongLived:         longLived,
			FederatedVia:        federated,
			SourcePath:          path,
			SourceFormat:        FormatYAML,
		})
		// Wipe inline secrets we touched.
		if usr.Token != "" {
			wipeStringInto(&usr.Token)
		}
		if usr.Password != "" {
			wipeStringInto(&usr.Password)
		}
	}
	return out
}

// classifyKubeconfigUser returns (CredentialType, isLongLived, federatedVia).
// Priority: exec (federation) > token (bearer) > client-cert (mTLS) >
// basic-auth > auth-provider (legacy OIDC/GCP).
func classifyKubeconfigUser(u kubeconfigUser) (CredentialType, bool, string) {
	switch {
	case u.Exec != nil:
		// Exec plugin = federated cred (AWS IAM, GCP gke-gcloud-auth-plugin,
		// Azure kubelogin). Short-lived by design.
		return CredOAuthAccess, false, "exec-plugin:" + u.Exec.Command
	case u.Token != "" || u.TokenFile != "":
		return CredBearerToken, true, ""
	case u.ClientCertificateData != "":
		return CredAccessKey, true, "" // mTLS cert = long-lived ID
	case u.Username != "":
		return CredBasicAuth, true, ""
	case len(u.AuthProvider) > 0:
		return CredOAuthRefresh, false, "auth-provider"
	}
	return CredUnknown, false, ""
}

// wipeStringInto attempts to zero a string's backing array. Go strings
// are immutable so this is best-effort; for genuine secret-handling
// callers should use byte slices throughout.
func wipeStringInto(s *string) {
	// We can't actually overwrite the backing store of an immutable
	// string. The defer wipe(data) on the entire YAML buffer is what
	// actually zeros the bytes — this helper exists to document intent
	// and to ease a future refactor that flows secrets as []byte.
	*s = ""
}
