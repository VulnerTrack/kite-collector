package cloudcreds

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- fakes --------------------------------------------------------

type fakeEntry struct {
	name string
	dir  bool
}

func (f fakeEntry) Name() string { return f.name }
func (f fakeEntry) IsDir() bool  { return f.dir }
func (f fakeEntry) Type() os.FileMode {
	if f.dir {
		return os.ModeDir
	}
	return 0
}
func (f fakeEntry) Info() (os.FileInfo, error) { return nil, nil }

// fakeCollector returns a fixed set (or error) for chain tests.
type fakeCollector struct {
	name  string
	creds []Credential
	err   error
}

func (f fakeCollector) Name() string { return f.name }
func (f fakeCollector) Collect(context.Context) ([]Credential, error) {
	return f.creds, f.err
}

// -- enum strings pinned to host_cloud_credentials CHECK enums ----

func TestProviderEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ProviderAWS), "aws"},
		{string(ProviderGCP), "gcp"},
		{string(ProviderAzure), "azure"},
		{string(ProviderKubernetes), "kubernetes"},
		{string(ProviderKubeconfig), "kubeconfig"},
		{string(ProviderGitHub), "github"},
		{string(ProviderGitLab), "gitlab"},
		{string(ProviderBitbucket), "bitbucket"},
		{string(ProviderDocker), "docker"},
		{string(ProviderHelm), "helm"},
		{string(ProviderNPM), "npm"},
		{string(ProviderPyPI), "pypi"},
		{string(ProviderTerraformCloud), "terraform-cloud"},
		{string(ProviderVault), "hashicorp-vault"},
		{string(ProviderCloudflare), "cloudflare"},
		{string(ProviderDigitalOcean), "digitalocean"},
		{string(ProviderUnknown), "unknown"},
	}
	for _, p := range pairs {
		assert.Equal(t, p.want, p.got)
	}
}

func TestCredentialTypeEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(CredAccessKey), "access-key"},
		{string(CredSessionToken), "session-token"},
		{string(CredServiceAccountKey), "service-account-key"},
		{string(CredOAuthRefresh), "oauth-refresh-token"},
		{string(CredOAuthAccess), "oauth-access-token"},
		{string(CredSSOCache), "sso-cache"},
		{string(CredKubeconfigContext), "kubeconfig-context"},
		{string(CredBearerToken), "bearer-token"},
		{string(CredBasicAuth), "basic-auth"},
		{string(CredAPIKey), "api-key"},
		{string(CredUnknown), "unknown"},
	}
	for _, p := range pairs {
		assert.Equal(t, p.want, p.got)
	}
}

func TestSourceFormatEnumStrings(t *testing.T) {
	assert.Equal(t, "ini", string(FormatINI))
	assert.Equal(t, "json", string(FormatJSON))
	assert.Equal(t, "yaml", string(FormatYAML))
	assert.Equal(t, "unknown", string(FormatUnknown))
}

// -- AWS access-key classifiers -----------------------------------

func TestIsLikelyAWSAccessKeyID(t *testing.T) {
	valid := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ASIAIOSFODNN7EXAMPLE",
		"AGPAIOSFODNN7EXAMPLE",
		"AIDAIOSFODNN7EXAMPLE",
		"AROAIOSFODNN7EXAMPLE",
	}
	for _, s := range valid {
		assert.Truef(t, IsLikelyAWSAccessKeyID(s), "expected valid: %q", s)
	}
	invalid := []string{
		"AKIA",                   // too short
		"ABCDIOSFODNN7EXAMPLE",   // bad prefix
		"AKIAIOSFODNN7EXAMPL!",   // non-base32 char
		"AKIAiosfodnn7example",   // lowercase body
		"AKIAIOSFODNN7EXAMPLEXX", // too long
		"",
	}
	for _, s := range invalid {
		assert.Falsef(t, IsLikelyAWSAccessKeyID(s), "expected invalid: %q", s)
	}
}

func TestIsLongLivedAWSPrefix(t *testing.T) {
	assert.True(t, IsLongLivedAWSPrefix("AKIAIOSFODNN7EXAMPLE"))
	assert.False(t, IsLongLivedAWSPrefix("ASIAIOSFODNN7EXAMPLE"))
	assert.False(t, IsLongLivedAWSPrefix("AROAIOSFODNN7EXAMPLE"))
}

func TestSortCredentials(t *testing.T) {
	cs := []Credential{
		{Provider: ProviderKubeconfig, SourcePath: "/z", Profile: "b"},
		{Provider: ProviderAWS, SourcePath: "/b", Profile: "a"},
		{Provider: ProviderAWS, SourcePath: "/a", Profile: "z"},
		{Provider: ProviderAWS, SourcePath: "/a", Profile: "a"},
	}
	SortCredentials(cs)
	assert.Equal(t, ProviderAWS, cs[0].Provider)
	assert.Equal(t, "/a", cs[0].SourcePath)
	assert.Equal(t, "a", cs[0].Profile)
	assert.Equal(t, "/a", cs[1].SourcePath)
	assert.Equal(t, "z", cs[1].Profile)
	assert.Equal(t, ProviderKubeconfig, cs[3].Provider)
}

// -- homedir ------------------------------------------------------

func TestDefaultHomeRoots(t *testing.T) {
	roots := defaultHomeRoots()
	if runtime.GOOS == "linux" {
		assert.Equal(t, []string{"/home", "/root"}, roots)
	} else {
		assert.NotNil(t, roots)
	}
}

func TestIsSystemUserName(t *testing.T) {
	for _, n := range []string{
		"shared", "GUEST", "Public", "default",
		"all users", "defaultappuser", "defaultaccount", "wdagutilityaccount",
	} {
		assert.Truef(t, isSystemUserName(n), "expected system: %q", n)
	}
	assert.False(t, isSystemUserName("alice"))
}

func TestWalkHomes(t *testing.T) {
	readDir := func(p string) ([]os.DirEntry, error) {
		switch p {
		case "/home":
			return []os.DirEntry{
				fakeEntry{"alice", true},
				fakeEntry{"bob", true},
				fakeEntry{"shared", true},      // system → skip
				fakeEntry{".hidden", true},     // dot → skip
				fakeEntry{"readme.txt", false}, // file → skip
			}, nil
		case "/root":
			return []os.DirEntry{fakeEntry{"stuff", true}}, nil
		default:
			return nil, errors.New("nope")
		}
	}

	assert.Equal(t, []string{"/home/alice", "/home/bob"},
		walkHomes(readDir, []string{"/home"}))
	// A root literally named "root" is one home, not a parent.
	assert.Equal(t, []string{"/root"}, walkHomes(readDir, []string{"/root"}))
	// readDir error + basename root/var → treat root as a single home.
	assert.Equal(t, []string{"/missing/root"}, walkHomes(readDir, []string{"/missing/root"}))
	assert.Equal(t, []string{"/missing/var"}, walkHomes(readDir, []string{"/missing/var"}))
	// readDir error + other basename → nothing.
	assert.Empty(t, walkHomes(readDir, []string{"/missing/home"}))
}

// -- AWS collector ------------------------------------------------

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

func TestParseINI(t *testing.T) {
	data := []byte("; a comment\n" +
		"# another comment\n" +
		"orphan = value-before-section\n" +
		"[default]\n" +
		"Key_One = val1\n" +
		"\n" +
		"[prod]\n" +
		"key_two=val2\n" +
		"malformed-line-no-eq\n" +
		"=novalue\n")
	secs := parseINI(data)
	require.Len(t, secs, 2)
	assert.Equal(t, "default", secs[0].name)
	require.Len(t, secs[0].pairs, 1)
	assert.Equal(t, "key_one", secs[0].pairs[0].key) // lowercased
	assert.Equal(t, "val1", secs[0].pairs[0].val)
	assert.Equal(t, "prod", secs[1].name)
	require.Len(t, secs[1].pairs, 1)
	assert.Equal(t, "val2", secs[1].pairs[0].val)
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	wipe(b)
	for _, c := range b {
		assert.Equal(t, byte(0), c)
	}
}

func TestAWSCollector(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "alice", ".aws", "credentials"),
		"[default]\n"+
			"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"+
			"aws_secret_access_key = wJalrXUtnFEMIsecretkeyEXAMPLE\n"+
			"\n"+
			"[staging]\n"+
			"aws_access_key_id = ASIAIOSFODNN7EXAMPLE\n"+
			"aws_session_token = FQoGZXIvYXdzsessiontoken\n"+
			"\n"+
			"[secretonly]\n"+
			"aws_secret_access_key = onlysecret\n")
	writeFile(t, filepath.Join(base, "alice", ".aws", "config"),
		"[default]\n"+
			"region = us-east-1\n"+
			"\n"+
			"[profile prod]\n"+
			"role_arn = arn:aws:iam::123456789012:role/Prod\n"+
			"sso_session = corp-sso\n"+
			"mfa_serial = arn:aws:iam::123456789012:mfa/alice\n"+
			"region = us-west-2\n"+
			"\n"+
			"[profile ci]\n"+
			"credential_source = Ec2InstanceMetadata\n")

	c := &awsCollector{
		homeRoots: []string{base},
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	assert.Equal(t, "aws-files", c.Name())
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 6) // 3 credentials sections + 3 config sections

	by := map[string]Credential{}
	for _, cr := range got {
		by[cr.SourcePath+"|"+cr.Profile] = cr
	}
	credPath := filepath.Join(base, "alice", ".aws", "credentials")
	cfgPath := filepath.Join(base, "alice", ".aws", "config")

	def := by[credPath+"|default"]
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", def.KeyID)
	assert.True(t, def.IsLongLived)
	assert.Equal(t, CredAccessKey, def.CredentialType)
	assert.Equal(t, "alice", def.OwnerUser)
	assert.Equal(t, FormatINI, def.SourceFormat)

	stg := by[credPath+"|staging"]
	assert.Equal(t, CredSessionToken, stg.CredentialType)
	assert.True(t, stg.SessionTokenPresent)
	assert.False(t, stg.IsLongLived)

	so := by[credPath+"|secretonly"]
	assert.Equal(t, CredUnknown, so.CredentialType) // no key id, no token

	prod := by[cfgPath+"|prod"]
	assert.Equal(t, "arn:aws:iam::123456789012:role/Prod", prod.RoleARN)
	assert.Equal(t, "sso", prod.FederatedVia)
	assert.Equal(t, CredSSOCache, prod.CredentialType)
	assert.True(t, prod.HasMFA)
	assert.Equal(t, "us-west-2", prod.Region)

	ci := by[cfgPath+"|ci"]
	assert.Equal(t, "iam-instance-role", ci.FederatedVia)
}

func TestAWSCollectorMissingFilesOK(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "alice"), 0o755))
	c := &awsCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestAWSCollectorContextCancelled(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "alice"), 0o755))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &awsCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	_, err := c.Collect(ctx)
	assert.Error(t, err)
}

// -- GCP collector ------------------------------------------------

func TestDecodeGCPCredential(t *testing.T) {
	sa := `{"type":"service_account","project_id":"sa-proj",` +
		`"client_email":"sa@sa-proj.iam.gserviceaccount.com","private_key_id":"kid-123"}`
	cred, ok := decodeGCPCredential([]byte(sa), "default")
	require.True(t, ok)
	assert.Equal(t, ProviderGCP, cred.Provider)
	assert.Equal(t, CredServiceAccountKey, cred.CredentialType)
	assert.True(t, cred.IsLongLived)
	assert.Equal(t, "sa-proj", cred.AccountID)
	assert.Equal(t, "kid-123", cred.KeyID)
	assert.Equal(t, "sa@sa-proj.iam.gserviceaccount.com", cred.RoleARN)

	au := `{"type":"authorized_user","project_id":"u-proj","client_id":"cid"}`
	cred, ok = decodeGCPCredential([]byte(au), "acct")
	require.True(t, ok)
	assert.Equal(t, CredOAuthRefresh, cred.CredentialType)
	assert.Equal(t, "oauth", cred.FederatedVia)
	assert.False(t, cred.IsLongLived)

	ext := `{"type":"external_account","project_id":"x"}`
	cred, ok = decodeGCPCredential([]byte(ext), "acct")
	require.True(t, ok)
	assert.Equal(t, CredOAuthAccess, cred.CredentialType)
	assert.Equal(t, "workload-identity-federation", cred.FederatedVia)

	other := `{"type":"mystery"}`
	cred, ok = decodeGCPCredential([]byte(other), "acct")
	require.True(t, ok)
	assert.Equal(t, CredUnknown, cred.CredentialType)

	_, ok = decodeGCPCredential([]byte("{not-json"), "acct")
	assert.False(t, ok)
}

func TestGCPCollector(t *testing.T) {
	base := t.TempDir()
	gcloud := filepath.Join(base, "alice", ".config", "gcloud")
	writeFile(t, filepath.Join(gcloud, "application_default_credentials.json"),
		`{"type":"authorized_user","project_id":"u-proj","client_id":"cid"}`)
	writeFile(t, filepath.Join(gcloud, "legacy_credentials", "acct1", "adc.json"),
		`{"type":"service_account","project_id":"sa-proj","client_email":"sa@x.iam","private_key_id":"kid"}`)
	// A legacy dir without adc.json and a stray file — both ignored.
	require.NoError(t, os.MkdirAll(filepath.Join(gcloud, "legacy_credentials", "noadc"), 0o755))
	writeFile(t, filepath.Join(gcloud, "legacy_credentials", "stray.txt"), "x")

	c := &gcpCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	assert.Equal(t, "gcp-files", c.Name())
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2)

	var haveSA, haveADC bool
	for _, cr := range got {
		assert.Equal(t, "alice", cr.OwnerUser)
		switch cr.CredentialType {
		case CredServiceAccountKey:
			haveSA = true
			assert.Equal(t, "sa-proj", cr.AccountID)
		case CredOAuthRefresh:
			haveADC = true
			assert.Equal(t, "u-proj", cr.AccountID)
		case CredAccessKey, CredSessionToken, CredOAuthAccess,
			CredSSOCache, CredKubeconfigContext, CredBearerToken,
			CredBasicAuth, CredAPIKey, CredUnknown:
			t.Fatalf("unexpected gcp cred type %q", cr.CredentialType)
		}
	}
	assert.True(t, haveSA, "expected service-account cred")
	assert.True(t, haveADC, "expected ADC oauth cred")
}

func TestGCPCollectorUnparseableADC(t *testing.T) {
	base := t.TempDir()
	gcloud := filepath.Join(base, "alice", ".config", "gcloud")
	writeFile(t, filepath.Join(gcloud, "application_default_credentials.json"), "{broken")
	c := &gcpCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

// -- Kubeconfig collector -----------------------------------------

func TestClassifyKubeconfigUser(t *testing.T) {
	execUser := kubeconfigUser{Exec: &kubeconfigExec{Command: "aws"}}
	ct, ll, fed := classifyKubeconfigUser(execUser)
	assert.Equal(t, CredOAuthAccess, ct)
	assert.False(t, ll)
	assert.Equal(t, "exec-plugin:aws", fed)

	ct, ll, fed = classifyKubeconfigUser(kubeconfigUser{Token: "tok"})
	assert.Equal(t, CredBearerToken, ct)
	assert.True(t, ll)
	assert.Empty(t, fed)

	ct, _, _ = classifyKubeconfigUser(kubeconfigUser{TokenFile: "/var/run/token"})
	assert.Equal(t, CredBearerToken, ct)

	ct, ll, _ = classifyKubeconfigUser(kubeconfigUser{ClientCertificateData: "b64"})
	assert.Equal(t, CredAccessKey, ct)
	assert.True(t, ll)

	ct, _, _ = classifyKubeconfigUser(kubeconfigUser{Username: "alice"})
	assert.Equal(t, CredBasicAuth, ct)

	ct, ll, fed = classifyKubeconfigUser(kubeconfigUser{AuthProvider: map[string]any{"name": "oidc"}})
	assert.Equal(t, CredOAuthRefresh, ct)
	assert.False(t, ll)
	assert.Equal(t, "auth-provider", fed)

	ct, ll, fed = classifyKubeconfigUser(kubeconfigUser{})
	assert.Equal(t, CredUnknown, ct)
	assert.False(t, ll)
	assert.Empty(t, fed)
}

func TestWipeStringInto(t *testing.T) {
	s := "secret"
	wipeStringInto(&s)
	assert.Empty(t, s)
}

const kubeconfigBody = `apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev-cluster
  cluster:
    server: https://1.2.3.4:6443
users:
- name: dev-user
  user:
    token: bearer-token-value
- name: exec-user
  user:
    exec:
      command: aws
contexts:
- name: dev
  context:
    cluster: dev-cluster
    user: dev-user
- name: exec-ctx
  context:
    cluster: dev-cluster
    user: exec-user
`

func TestKubeconfigCollector(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "alice", ".kube", "config"), kubeconfigBody)

	c := &kubeconfigCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	assert.Equal(t, "kubeconfig-files", c.Name())
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2)

	by := map[string]Credential{}
	for _, cr := range got {
		by[cr.Profile] = cr
		assert.Equal(t, ProviderKubeconfig, cr.Provider)
		assert.Equal(t, "https://1.2.3.4:6443", cr.AccountID)
		assert.Equal(t, FormatYAML, cr.SourceFormat)
	}
	dev := by["dev"]
	assert.Equal(t, CredBearerToken, dev.CredentialType)
	assert.True(t, dev.IsLongLived)
	assert.True(t, dev.SessionTokenPresent)

	ex := by["exec-ctx"]
	assert.Equal(t, CredOAuthAccess, ex.CredentialType)
	assert.Equal(t, "exec-plugin:aws", ex.FederatedVia)
}

func TestKubeconfigCollectorRejectsNonConfig(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "alice", ".kube", "config"),
		"kind: Secret\napiVersion: v1\n")
	c := &kubeconfigCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestKubeconfigCollectorInvalidYAML(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "alice", ".kube", "config"),
		"::: not yaml :::\n\tbad-indent")
	c := &kubeconfigCollector{homeRoots: []string{base}, readFile: os.ReadFile, readDir: os.ReadDir}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

// -- stubs --------------------------------------------------------

func TestStubCollectors(t *testing.T) {
	stubs := []Collector{
		NewAzureCollector(),
		NewGitHubCollector(),
		NewDockerCollector(),
		NewNPMCollector(),
		NewTerraformCloudCollector(),
	}
	wantNames := map[string]bool{
		"azure-stub": true, "github-stub": true, "docker-stub": true,
		"npm-stub": true, "tfc-stub": true,
	}
	for _, s := range stubs {
		assert.Truef(t, wantNames[s.Name()], "unexpected stub name %q", s.Name())
		got, err := s.Collect(context.Background())
		require.NoError(t, err)
		assert.Empty(t, got)
	}
}

// -- chain --------------------------------------------------------

func TestChainCollectorConcatenatesAndSorts(t *testing.T) {
	chain := &chainCollector{collectors: []Collector{
		fakeCollector{name: "b", creds: []Credential{
			{Provider: ProviderKubeconfig, SourcePath: "/z", Profile: "a"},
		}},
		fakeCollector{name: "a", creds: []Credential{
			{Provider: ProviderAWS, SourcePath: "/a", Profile: "a"},
		}},
	}}
	assert.Equal(t, "cloud-credentials", chain.Name())
	got, err := chain.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2)
	// Sorted: AWS before Kubeconfig.
	assert.Equal(t, ProviderAWS, got[0].Provider)
	assert.Equal(t, ProviderKubeconfig, got[1].Provider)
}

func TestChainCollectorSkipsFailingSource(t *testing.T) {
	chain := &chainCollector{collectors: []Collector{
		fakeCollector{name: "boom", err: errors.New("kaboom")},
		fakeCollector{name: "ok", creds: []Credential{
			{Provider: ProviderAWS, SourcePath: "/a", Profile: "a"},
		}},
	}}
	got, err := chain.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ProviderAWS, got[0].Provider)
}

func TestChainCollectorCapReached(t *testing.T) {
	many := make([]Credential, MaxCredentials+500)
	for i := range many {
		many[i] = Credential{Provider: ProviderAWS, SourcePath: "/a", Profile: "p"}
	}
	chain := &chainCollector{collectors: []Collector{
		fakeCollector{name: "flood", creds: many},
		fakeCollector{name: "extra", creds: []Credential{
			{Provider: ProviderGCP, SourcePath: "/b", Profile: "q"},
		}},
	}}
	got, err := chain.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, MaxCredentials)
}

func TestChainCollectorContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	chain := &chainCollector{collectors: []Collector{
		fakeCollector{name: "x", creds: []Credential{
			{Provider: ProviderAWS, SourcePath: "/a", Profile: "a"},
		}},
	}}
	_, err := chain.Collect(ctx)
	assert.Error(t, err)
}

func TestNewChainCollectorWiresDefaults(t *testing.T) {
	chain, ok := NewChainCollector().(*chainCollector)
	require.True(t, ok)
	assert.Len(t, chain.collectors, 8)
	assert.Equal(t, "cloud-credentials", chain.Name())
}

func TestConstructorsReturnNonNil(t *testing.T) {
	assert.NotNil(t, NewAWSCollector())
	assert.NotNil(t, NewGCPCollector())
	assert.NotNil(t, NewKubeconfigCollector())
	assert.Equal(t, MaxCredentials, 1024)
}
