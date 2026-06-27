package wingithubcli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("github.com:\n  user: a\n"))
	b := HashContents([]byte("github.com:\n  user: a\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestTokenFamilyPrefix(t *testing.T) {
	cases := map[string]string{
		"ghp_aaaaaaaaaaaa": "ghp_",
		"gho_bbbbbbbbbbbb": "gho_",
		"ghu_cccccccccccc": "ghu_",
		"ghs_dddddddddddd": "ghs_",
		"ghr_eeeeeeeeeeee": "ghr_",
		"":                 "",
		"abc":              "",
		"   ghp_xxx   ":    "ghp_",
	}
	for in, want := range cases {
		if got := TokenFamilyPrefix(in); got != want {
			t.Fatalf("TokenFamilyPrefix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsFirstPartyHost(t *testing.T) {
	yes := []string{"github.com", "api.github.com", "ghe.com", "GitHub.com"}
	no := []string{"", "github.example.com", "ghes.acme.io"}
	for _, v := range yes {
		if !IsFirstPartyHost(v) {
			t.Fatalf("expected first-party: %q", v)
		}
	}
	for _, v := range no {
		if IsFirstPartyHost(v) {
			t.Fatalf("expected NOT first-party: %q", v)
		}
	}
}

func TestAnnotateTokenWorldReadable(t *testing.T) {
	r := Row{Host: "github.com", IsOAuthTokenPresent: true, FileMode: 0o644}
	AnnotateSecurity(&r)
	if !r.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !r.IsUnencryptedToken || !r.IsCredentialExposureRisk {
		t.Fatalf("token + world-readable must flag: %+v", r)
	}
	if r.IsEnterpriseHost {
		t.Fatal("github.com is first-party")
	}
}

func TestAnnotateTokenGroupReadable(t *testing.T) {
	r := Row{Host: "github.com", IsOAuthTokenPresent: true, FileMode: 0o640}
	AnnotateSecurity(&r)
	if !r.IsGroupReadable || r.IsWorldReadable {
		t.Fatalf("0o640 must flag group only: %+v", r)
	}
	if !r.IsUnencryptedToken {
		t.Fatal("token + group-readable must flag")
	}
}

func TestAnnotateToken0600Clean(t *testing.T) {
	r := Row{Host: "github.com", IsOAuthTokenPresent: true, FileMode: 0o600}
	AnnotateSecurity(&r)
	if r.IsWorldReadable || r.IsGroupReadable || r.IsUnencryptedToken {
		t.Fatalf("0o600 must NOT flag: %+v", r)
	}
}

func TestAnnotateEnterpriseHost(t *testing.T) {
	r := Row{Host: "github.acme.io", IsOAuthTokenPresent: true, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsEnterpriseHost {
		t.Fatal("enterprise host must flag")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 enterprise host alone is NOT immediate-incident")
	}
}

// -- ParseHostsYAML ------------------------------------------------

func TestParseHostsYAMLTypical(t *testing.T) {
	body := []byte(`github.com:
    user: alice
    oauth_token: ghp_xxxxxxxxxxxx
    git_protocol: ssh
github.acme.io:
    user: bob
    oauth_token: ghu_yyyyyyyyyyyy
    git_protocol: https
`)
	got := ParseHostsYAML(body)
	if len(got) != 2 {
		t.Fatalf("rows=%d, want 2: %+v", len(got), got)
	}
	byHost := map[string]Row{}
	for _, r := range got {
		byHost[r.Host] = r
	}
	gh := byHost["github.com"]
	if !gh.IsOAuthTokenPresent || gh.TokenFamily != "ghp_" {
		t.Fatalf("github.com: %+v", gh)
	}
	if gh.GhUser != "alice" || gh.GitProtocol != "ssh" {
		t.Fatalf("github.com fields: %+v", gh)
	}
	ent := byHost["github.acme.io"]
	if ent.TokenFamily != "ghu_" {
		t.Fatalf("enterprise prefix=%q", ent.TokenFamily)
	}
}

func TestParseHostsYAMLMalformedReturnsEmpty(t *testing.T) {
	body := []byte("this:is\n  not: : valid yaml: [\n")
	got := ParseHostsYAML(body)
	if len(got) != 0 {
		t.Fatalf("malformed must yield empty, got %+v", got)
	}
}

func TestParseHostsYAMLNoToken(t *testing.T) {
	body := []byte(`github.com:
    user: alice
    git_protocol: https
`)
	got := ParseHostsYAML(body)
	if len(got) != 1 || got[0].IsOAuthTokenPresent || got[0].TokenFamily != "" {
		t.Fatalf("no-token shape: %+v", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestFileCollectorWalksPerUserAndEnv(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's hosts.yml: token + world-readable.
	aliceHosts := filepath.Join(append([]string{usersBase, "alice"},
		HostsRelComponentsPosix()...)...)
	must(t, os.MkdirAll(filepath.Dir(aliceHosts), 0o755))
	must(t, os.WriteFile(aliceHosts, []byte(`github.com:
    user: alice
    oauth_token: ghp_alicealicealice
    git_protocol: ssh
`), 0o644))

	// Env-supplied GH_CONFIG_DIR.
	envDir := filepath.Join(tmp, "ci-gh")
	must(t, os.MkdirAll(envDir, 0o755))
	envHosts := filepath.Join(envDir, "hosts.yml")
	must(t, os.WriteFile(envHosts, []byte(`github.acme.io:
    user: ci
    oauth_token: ghs_cicicicicicicici
    git_protocol: https
`), 0o600))

	// Public profile must be skipped.
	pubHosts := filepath.Join(append([]string{usersBase, "Public"},
		HostsRelComponentsPosix()...)...)
	must(t, os.MkdirAll(filepath.Dir(pubHosts), 0o755))
	must(t, os.WriteFile(pubHosts, []byte(`github.com:
    user: skip
    oauth_token: ghp_skip
`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv: func(k string) string {
			if k == "GH_CONFIG_DIR" {
				return envDir
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
	if len(got) != 2 {
		t.Fatalf("want 2 (alice + env), got %d: %+v", len(got), got)
	}

	var aliceRow, ciRow Row
	for _, r := range got {
		if r.UserProfile == "alice" {
			aliceRow = r
		}
		if r.FilePath == envHosts {
			ciRow = r
		}
	}
	if aliceRow.FilePath == "" {
		t.Fatal("alice row missing")
	}
	if !aliceRow.IsUnencryptedToken || !aliceRow.IsCredentialExposureRisk {
		t.Fatalf("alice 0o644 + token must flag: %+v", aliceRow)
	}
	if aliceRow.TokenFamily != "ghp_" {
		t.Fatalf("alice family=%q", aliceRow.TokenFamily)
	}

	if ciRow.FilePath == "" {
		t.Fatal("env-supplied hosts missing — GH_CONFIG_DIR not honoured")
	}
	if !ciRow.IsEnterpriseHost {
		t.Fatal("github.acme.io must flag enterprise")
	}
	if ciRow.IsUnencryptedToken {
		t.Fatal("0o600 env-hosts must NOT flag unencrypted")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
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

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", Host: "github.com"},
		{FilePath: "a", Host: "z.com"},
		{FilePath: "a", Host: "a.com"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].Host != "a.com" {
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
