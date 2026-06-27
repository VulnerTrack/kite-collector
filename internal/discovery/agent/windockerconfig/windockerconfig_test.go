package windockerconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedEntryKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EntryAuth), "auth"},
		{string(EntryCredHelper), "cred-helper"},
		{string(EntryProxy), "proxy"},
		{string(EntryCLIPluginDir), "cli-plugin-dir"},
		{string(EntryCLIConfig), "cli-config"},
		{string(EntryUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("entry_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`{}`))
	b := HashContents([]byte(`{}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsSecureCredentialHelperName(t *testing.T) {
	hit := []string{
		"osxkeychain", "OsXKeyChain", "docker-credential-osxkeychain",
		"wincred", "secretservice", "pass", "ecr-login", "gcloud", "desktop",
	}
	for _, n := range hit {
		if !IsSecureCredentialHelperName(n) {
			t.Fatalf("%q must flag secure", n)
		}
	}
	miss := []string{
		"", "random-helper", "evil-helper", "shell",
	}
	for _, n := range miss {
		if IsSecureCredentialHelperName(n) {
			t.Fatalf("%q must NOT flag secure", n)
		}
	}
}

func TestIsExternalProxyTarget(t *testing.T) {
	external := []string{
		"http://attacker.example.com:3128",
		"http://1.2.3.4:8080",
		"https://proxy.public.example.com",
	}
	for _, p := range external {
		if !IsExternalProxyTarget(p) {
			t.Fatalf("%q must flag external", p)
		}
	}
	internal := []string{
		"http://10.0.0.5:3128",
		"http://172.16.0.5:3128",
		"http://192.168.1.5:3128",
		"http://127.0.0.1:3128",
		"http://localhost:3128",
		"",
	}
	for _, p := range internal {
		if IsExternalProxyTarget(p) {
			t.Fatalf("%q must NOT flag external", p)
		}
	}
}

func TestIsWorldWritableDir(t *testing.T) {
	hit := []string{
		`C:\Users\Public\plugins`,
		`C:\Windows\Temp\plugins`,
		"/tmp/docker-plugins",
		"/var/tmp/foo",
		`%TEMP%\plugins`,
	}
	for _, d := range hit {
		if !IsWorldWritableDir(d) {
			t.Fatalf("%q must flag world-writable", d)
		}
	}
	miss := []string{
		`C:\Program Files\Docker\plugins`,
		"/usr/local/lib/docker/cli-plugins",
		"",
	}
	for _, d := range miss {
		if IsWorldWritableDir(d) {
			t.Fatalf("%q must NOT flag world-writable", d)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateAuthWorldReadable(t *testing.T) {
	e := Entry{
		EntryKind:     EntryAuth,
		EntryName:     "https://index.docker.io/v1/",
		HasInlineAuth: true,
		FileMode:      0o644,
	}
	AnnotateSecurity(&e)
	if !e.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("inline auth + world-readable must flag")
	}
}

func TestAnnotateAuthMode0600IsCleanRollup(t *testing.T) {
	e := Entry{
		EntryKind:     EntryAuth,
		HasInlineAuth: true,
		FileMode:      0o600,
	}
	AnnotateSecurity(&e)
	if e.IsWorldReadable || e.IsGroupReadable {
		t.Fatal("0o600 must NOT flag")
	}
	if e.IsCredentialExposureRisk {
		t.Fatal("inline auth in 0o600 alone is NOT headline incident")
	}
}

func TestAnnotateInsecureCredHelper(t *testing.T) {
	e := Entry{
		EntryKind:            EntryCredHelper,
		EntryName:            "<global>",
		CredentialHelperName: "evil-helper",
		FileMode:             0o600,
	}
	AnnotateSecurity(&e)
	if e.IsSecureCredentialHelper {
		t.Fatal("evil-helper must NOT flag secure")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("insecure cred helper must flag")
	}
}

func TestAnnotateSecureCredHelperClean(t *testing.T) {
	e := Entry{
		EntryKind:            EntryCredHelper,
		CredentialHelperName: "osxkeychain",
		FileMode:             0o644,
	}
	AnnotateSecurity(&e)
	if !e.IsSecureCredentialHelper {
		t.Fatal("osxkeychain must flag secure")
	}
	if e.IsCredentialExposureRisk {
		t.Fatal("secure helper must NOT flag credential risk (file mode doesn't matter for helper rows)")
	}
}

func TestAnnotateExternalProxy(t *testing.T) {
	e := Entry{
		EntryKind: EntryProxy,
		EntryName: "default.httpsProxy",
		ProxyURL:  "https://attacker.example.com:8080",
	}
	AnnotateSecurity(&e)
	if !e.ProxyTargetIsExternal {
		t.Fatal("external URL must flag")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("external proxy must flag exfil risk")
	}
}

func TestAnnotatePluginDirWorldWritable(t *testing.T) {
	e := Entry{
		EntryKind:    EntryCLIPluginDir,
		EntryName:    "/tmp/plugins",
		CLIPluginDir: "/tmp/plugins",
	}
	AnnotateSecurity(&e)
	if !e.IsWorldWritableDir {
		t.Fatal("/tmp must flag")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("world-writable plugin dir must flag")
	}
}

// -- ParseConfig end-to-end -----------------------------------------

func TestParseConfigTypical(t *testing.T) {
	body := []byte(`{
        "auths": {
            "https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"},
            "ghcr.io": {"identitytoken": "eyJ..."}
        },
        "credsStore": "desktop",
        "credHelpers": {
            "123456789012.dkr.ecr.us-east-1.amazonaws.com": "ecr-login",
            "untrusted.example.com": "evil-helper"
        },
        "proxies": {
            "default": {
                "httpProxy": "http://10.0.0.5:3128",
                "httpsProxy": "https://attacker.example.com:443"
            }
        },
        "cliPluginsExtraDirs": ["/tmp/docker-plugins", "/usr/local/lib/docker/cli-plugins"],
        "experimental": "enabled"
    }`)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 2 auths + 1 global helper + 2 cred-helpers + 2 proxies +
	// 2 plugin-dirs + 1 cli-config = 10.
	if len(got) != 10 {
		t.Fatalf("rows=%d: %+v", len(got), got)
	}

	kinds := map[EntryKind]int{}
	for _, e := range got {
		kinds[e.EntryKind]++
	}
	if kinds[EntryAuth] != 2 || kinds[EntryCredHelper] != 3 ||
		kinds[EntryProxy] != 2 || kinds[EntryCLIPluginDir] != 2 ||
		kinds[EntryCLIConfig] != 1 {
		t.Fatalf("kind counts wrong: %+v", kinds)
	}

	// Verify inline auth detection on index.docker.io.
	var dockerHub Entry
	for _, e := range got {
		if e.EntryKind == EntryAuth &&
			e.EntryName == "https://index.docker.io/v1/" {
			dockerHub = e
		}
	}
	if !dockerHub.HasInlineAuth {
		t.Fatalf("docker-hub auth must flag inline: %+v", dockerHub)
	}
	if dockerHub.RegistryHost != "index.docker.io" {
		t.Fatalf("registry_host=%q (scheme/path not stripped)", dockerHub.RegistryHost)
	}

	// Verify identity-token-only detection on ghcr.
	var ghcr Entry
	for _, e := range got {
		if e.EntryKind == EntryAuth && e.EntryName == "ghcr.io" {
			ghcr = e
		}
	}
	if ghcr.HasInlineAuth {
		t.Fatal("ghcr has no auth field — must NOT flag inline")
	}
	if !ghcr.HasIdentityToken {
		t.Fatal("ghcr identitytoken must flag")
	}
}

func TestParseConfigBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`{"auths":{"x":{"auth":"y"}}}`)...)
	got, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
}

func TestParseConfigEmpty(t *testing.T) {
	if _, err := ParseConfig(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseConfigMalformed(t *testing.T) {
	if _, err := ParseConfig([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksPerUserAndEnv(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's docker config with inline auth + world-readable mode.
	aliceDocker := filepath.Join(usersBase, "alice", ".docker", "config.json")
	must(t, os.MkdirAll(filepath.Dir(aliceDocker), 0o755))
	must(t, os.WriteFile(aliceDocker, []byte(`{"auths":{"reg.example.com":{"auth":"dXNlcjpwYXNz"}}}`), 0o644))

	// Env-supplied DOCKER_CONFIG override.
	envDir := filepath.Join(tmp, "extra-docker")
	envFile := filepath.Join(envDir, "config.json")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(envFile, []byte(`{"credsStore":"evil-helper"}`), 0o600))

	// Public profile must be skipped.
	must(t, os.MkdirAll(filepath.Join(usersBase, "Public", ".docker"), 0o755))
	must(t, os.WriteFile(filepath.Join(usersBase, "Public", ".docker", "config.json"),
		[]byte(`{"auths":{"skip":{"auth":"x"}}}`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv: func(k string) string {
			if k == "DOCKER_CONFIG" {
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
	// alice: 1 auth. env: 1 cred-helper. Public: skipped. Total = 2.
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(got), got)
	}

	var aliceAuth Entry
	for _, e := range got {
		if e.UserProfile == "alice" && e.EntryKind == EntryAuth {
			aliceAuth = e
		}
	}
	if aliceAuth.FilePath == "" {
		t.Fatal("alice auth row missing")
	}
	if !aliceAuth.IsCredentialExposureRisk {
		t.Fatalf("alice inline auth + world-readable must flag: %+v", aliceAuth)
	}

	var envHelper Entry
	for _, e := range got {
		if e.EntryKind == EntryCredHelper {
			envHelper = e
		}
	}
	if envHelper.FilePath == "" {
		t.Fatal("env-supplied cred-helper row missing — DOCKER_CONFIG not honoured")
	}
	if envHelper.IsSecureCredentialHelper {
		t.Fatal("evil-helper must NOT flag secure")
	}
	if !envHelper.IsCredentialExposureRisk {
		t.Fatal("insecure helper must flag credential risk")
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

// -- SortEntries ----------------------------------------------------

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "z", EntryKind: EntryAuth, EntryName: "a"},
		{FilePath: "a", EntryKind: EntryProxy, EntryName: "a"},
		{FilePath: "a", EntryKind: EntryAuth, EntryName: "a"},
	}
	SortEntries(in)
	if in[0].FilePath != "a" || in[0].EntryKind != EntryAuth {
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
