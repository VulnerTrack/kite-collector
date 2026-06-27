package winkubeconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedEntryKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EntryCluster), "cluster"},
		{string(EntryUser), "user"},
		{string(EntryContext), "context"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("entry_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedAuthKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(AuthToken), "token"},
		{string(AuthCert), "cert"},
		{string(AuthExec), "exec"},
		{string(AuthAuthProvider), "auth-provider"},
		{string(AuthBasic), "basic"},
		{string(AuthNone), "none"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("auth_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("clusters: []"))
	b := HashContents([]byte("clusters: []"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsLoopbackURL(t *testing.T) {
	hit := []string{
		"https://127.0.0.1:6443",
		"https://localhost:6443",
		"http://[::1]:8080",
		"https://127.0.0.1",
		"https://localhost",
	}
	for _, s := range hit {
		if !IsLoopbackURL(s) {
			t.Fatalf("%q must flag loopback", s)
		}
	}
	miss := []string{
		"https://1.2.3.4:6443",
		"https://my-cluster.example.com:6443",
		"https://10.0.0.5",
		"",
		"not a url",
	}
	for _, s := range miss {
		if IsLoopbackURL(s) {
			t.Fatalf("%q must NOT flag loopback", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateInlineTokenProductionCluster(t *testing.T) {
	e := Entry{
		EntryKind:      EntryUser,
		HasInlineToken: true,
		Server:         "", // user rows don't carry Server; cluster row tested below
	}
	AnnotateSecurity(&e)
	// Inline-token-without-server still flags because the
	// `!IsLoopbackServer` short-circuits to true (empty server →
	// not loopback).
	if !e.IsCredentialExposureRisk {
		t.Fatalf("inline token + non-loopback must flag: %+v", e)
	}
}

func TestAnnotateInlineTokenLoopbackClusterClean(t *testing.T) {
	e := Entry{
		EntryKind:      EntryUser,
		HasInlineToken: true,
		Server:         "https://127.0.0.1:6443",
	}
	AnnotateSecurity(&e)
	// Loopback servers don't flag (think `kind` / `minikube`).
	if e.IsCredentialExposureRisk {
		t.Fatalf("inline token + loopback must NOT flag: %+v", e)
	}
}

func TestAnnotateInsecureTLSAlwaysFlags(t *testing.T) {
	e := Entry{
		EntryKind:               EntryCluster,
		Server:                  "https://1.2.3.4",
		IsInsecureSkipTLSVerify: true,
	}
	AnnotateSecurity(&e)
	if !e.IsCredentialExposureRisk {
		t.Fatal("insecure-skip-tls-verify must always flag")
	}
}

func TestAnnotateInlineTokenWorldReadable(t *testing.T) {
	e := Entry{
		HasInlineToken: true,
		Server:         "https://10.0.0.5",
		FileMode:       0o644,
	}
	AnnotateSecurity(&e)
	if !e.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("inline token + world-readable must flag")
	}
}

func TestAnnotateMode0600IsClean(t *testing.T) {
	e := Entry{
		HasInlineToken: true,
		Server:         "https://127.0.0.1",
		FileMode:       0o600,
	}
	AnnotateSecurity(&e)
	if e.IsWorldReadable || e.IsGroupReadable {
		t.Fatalf("0o600 must NOT flag: %+v", e)
	}
}

// -- ParseKubeconfig end-to-end --------------------------------------

func TestParseKubeconfigTypicalProduction(t *testing.T) {
	body := []byte(`apiVersion: v1
kind: Config
current-context: my-context
clusters:
- name: my-cluster
  cluster:
    server: https://1.2.3.4:6443
    certificate-authority-data: LS0tCk1JSWhlbGxv
- name: insecure-test
  cluster:
    server: https://insecure.example.com
    insecure-skip-tls-verify: true
users:
- name: my-user
  user:
    token: eyJabc.def.ghi
- name: cert-user
  user:
    client-certificate-data: LS0tCk1JSWhlbGxv
    client-key-data: LS0tCk1JSWhlbGxv
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: aws
      args: [eks, get-token, --cluster-name, my-cluster]
contexts:
- name: my-context
  context:
    cluster: my-cluster
    user: my-user
    namespace: production
- name: insecure-context
  context:
    cluster: insecure-test
    user: cert-user
`)
	got, err := ParseKubeconfig(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2+3+2 {
		t.Fatalf("rows=%d: %+v", len(got), got)
	}

	byName := map[string]Entry{}
	for _, e := range got {
		byName[string(e.EntryKind)+"/"+e.EntryName] = e
	}

	myCluster := byName["cluster/my-cluster"]
	if !myCluster.HasCertificateAuthority {
		t.Fatal("CA-data must flag has_certificate_authority")
	}
	if myCluster.IsInsecureSkipTLSVerify {
		t.Fatal("my-cluster has CA; must NOT flag insecure")
	}

	insecure := byName["cluster/insecure-test"]
	if !insecure.IsInsecureSkipTLSVerify {
		t.Fatal("insecure-test must flag insecure-skip-tls-verify")
	}

	tokenUser := byName["user/my-user"]
	if !tokenUser.HasInlineToken || tokenUser.AuthKind != AuthToken {
		t.Fatalf("token user wrong: %+v", tokenUser)
	}

	certUser := byName["user/cert-user"]
	if !certUser.HasInlineCertificate || certUser.AuthKind != AuthCert {
		t.Fatalf("cert user wrong: %+v", certUser)
	}

	execUser := byName["user/exec-user"]
	if !execUser.HasExecPlugin || execUser.AuthKind != AuthExec {
		t.Fatalf("exec user wrong: %+v", execUser)
	}
	if execUser.ExecCommand != "aws" {
		t.Fatalf("exec command=%q", execUser.ExecCommand)
	}

	myContext := byName["context/my-context"]
	if !myContext.IsCurrentContext {
		t.Fatal("my-context must flag current")
	}
	if myContext.ContextNamespace != "production" {
		t.Fatalf("namespace=%q", myContext.ContextNamespace)
	}

	insecureContext := byName["context/insecure-context"]
	if insecureContext.IsCurrentContext {
		t.Fatal("insecure-context must NOT flag current")
	}
}

func TestParseKubeconfigBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte("clusters:\n- name: x\n  cluster: {server: https://x}\n")...)
	got, err := ParseKubeconfig(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if len(got) != 1 || got[0].Server != "https://x" {
		t.Fatalf("BOM parse: %+v", got)
	}
}

func TestParseKubeconfigBasicAuthDetected(t *testing.T) {
	body := []byte(`users:
- name: u
  user:
    username: alice
    password: hunter2
`)
	got, err := ParseKubeconfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AuthKind != AuthBasic || !got[0].HasBasicAuth {
		t.Fatalf("basic auth wrong: %+v", got)
	}
}

func TestParseKubeconfigEmptyError(t *testing.T) {
	if _, err := ParseKubeconfig(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseKubeconfigMalformedError(t *testing.T) {
	if _, err := ParseKubeconfig([]byte(":\n  - [bogus\n")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksPerUserAndKubeconfigEnv(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's kubeconfig — inline token + non-loopback server.
	aliceKube := filepath.Join(usersBase, "alice", ".kube", "config")
	must(t, os.MkdirAll(filepath.Dir(aliceKube), 0o755))
	must(t, os.WriteFile(aliceKube, []byte(`apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://prod.example.com:6443
    certificate-authority-data: x
users:
- name: alice
  user:
    token: eyJtokenvalue
contexts:
- name: prod-ctx
  context:
    cluster: prod
    user: alice
current-context: prod-ctx
`), 0o644)) // world-readable!

	// Standalone via KUBECONFIG env.
	envFile := filepath.Join(tmp, "extra", "kubeconfig.yaml")
	must(t, os.MkdirAll(filepath.Dir(envFile), 0o755))
	must(t, os.WriteFile(envFile, []byte(`clusters:
- name: dev
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
`), 0o600))

	// Public profile must be skipped.
	must(t, os.MkdirAll(filepath.Join(usersBase, "Public", ".kube"), 0o755))
	must(t, os.WriteFile(filepath.Join(usersBase, "Public", ".kube", "config"),
		[]byte(`clusters: [{name: skip, cluster: {server: x}}]`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		rootFiles:  nil,
		getenv: func(k string) string {
			if k == "KUBECONFIG" {
				return envFile
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// alice: 1 cluster + 1 user + 1 context = 3.
	// env: 1 cluster.
	// Public: skipped.
	// Total = 4.
	if len(got) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(got), got)
	}

	var aliceToken Entry
	for _, e := range got {
		if e.EntryKind == EntryUser && e.EntryName == "alice" {
			aliceToken = e
		}
	}
	if aliceToken.FilePath == "" {
		t.Fatal("alice user row missing")
	}
	if !aliceToken.HasInlineToken {
		t.Fatalf("alice should have inline token: %+v", aliceToken)
	}
	if !aliceToken.IsWorldReadable {
		t.Fatalf("0o644 should flag world-readable: mode=%o", aliceToken.FileMode)
	}
	if !aliceToken.IsCredentialExposureRisk {
		t.Fatalf("inline token + world-readable must flag: %+v", aliceToken)
	}

	// Verify the env-supplied kubeconfig's insecure cluster flagged.
	var devCluster Entry
	for _, e := range got {
		if e.EntryKind == EntryCluster && e.EntryName == "dev" {
			devCluster = e
		}
	}
	if devCluster.FilePath == "" {
		t.Fatal("dev cluster row missing — KUBECONFIG env not honoured")
	}
	if !devCluster.IsInsecureSkipTLSVerify {
		t.Fatal("insecure-skip-tls-verify must propagate")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		rootFiles:  []string{"/nope-root"},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortEntries ----------------------------------------------------

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "z", EntryKind: EntryUser, EntryName: "a"},
		{FilePath: "a", EntryKind: EntryUser, EntryName: "z"},
		{FilePath: "a", EntryKind: EntryCluster, EntryName: "z"},
	}
	SortEntries(in)
	if in[0].FilePath != "a" || in[0].EntryKind != EntryCluster {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
