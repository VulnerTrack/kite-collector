package pkgrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedEcosystemStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EcosystemAPT), "apt"},
		{string(EcosystemYum), "yum"},
		{string(EcosystemDNF), "dnf"},
		{string(EcosystemZypper), "zypper"},
		{string(EcosystemAPK), "apk"},
		{string(EcosystemPacman), "pacman"},
		{string(EcosystemBrew), "brew"},
		{string(EcosystemPip), "pip"},
		{string(EcosystemNPM), "npm"},
		{string(EcosystemCargo), "cargo"},
		{string(EcosystemGem), "gem"},
		{string(EcosystemGoModule), "go-module"},
		{string(EcosystemSnap), "snap"},
		{string(EcosystemFlatpak), "flatpak"},
		{string(EcosystemWinget), "winget"},
		{string(EcosystemChocolatey), "chocolatey"},
		{string(EcosystemUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("ecosystem drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"main", "universe"}); got != `["main","universe"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("deb http://x y main\n"))
	b := HashContents([]byte("deb http://x y main\n"))
	if a != b || len(a) != 64 {
		t.Fatal("non-deterministic")
	}
}

func TestIsHTTPSURL(t *testing.T) {
	for _, in := range []string{"https://x", "HTTPS://Y/Z"} {
		if !IsHTTPSURL(in) {
			t.Fatalf("%q must be https", in)
		}
	}
	for _, in := range []string{"http://x", "ftp://x", "", "::bad::"} {
		if IsHTTPSURL(in) {
			t.Fatalf("%q must NOT be https", in)
		}
	}
}

func TestIsCanonicalUpstream(t *testing.T) {
	cases := []struct {
		ecosystem Ecosystem
		url       string
		want      bool
	}{
		{EcosystemAPT, "http://archive.ubuntu.com/ubuntu", true},
		{EcosystemAPT, "https://deb.debian.org/debian", true},
		{EcosystemAPT, "https://ppa.launchpad.net/example/ppa", false},
		{EcosystemDNF, "https://mirrors.fedoraproject.org/", true},
		{EcosystemDNF, "https://copr.fedorainfracloud.org/coprs/x", false},
		{EcosystemPip, "https://pypi.org/simple", true},
		{EcosystemPip, "http://internal-mirror/simple/", false},
		{EcosystemNPM, "https://registry.npmjs.org/", true},
		{EcosystemNPM, "https://npm.evil.test/", false},
	}
	for _, c := range cases {
		if got := IsCanonicalUpstream(c.ecosystem, c.url); got != c.want {
			t.Fatalf("%s %q = %v, want %v", c.ecosystem, c.url, got, c.want)
		}
	}
}

func TestAnnotateSecurityFlags(t *testing.T) {
	r := Repo{Ecosystem: EcosystemAPT, URL: "https://archive.ubuntu.com/ubuntu"}
	AnnotateSecurity(&r)
	if !r.IsHTTPS || r.IsThirdParty {
		t.Fatalf("canonical upstream over https wrong: %+v", r)
	}
	r = Repo{Ecosystem: EcosystemAPT, URL: "http://ppa.launchpad.net/x/ppa"}
	AnnotateSecurity(&r)
	if r.IsHTTPS || !r.IsThirdParty {
		t.Fatalf("ppa over http wrong: %+v", r)
	}
}

// -- APT parser ------------------------------------------------------------

func TestParseAPTSourcesListLegacy(t *testing.T) {
	body := []byte(`# main sources
deb http://archive.ubuntu.com/ubuntu jammy main universe
deb-src https://deb.debian.org/debian bookworm main
deb [signed-by=/usr/share/keyrings/x.gpg] https://example.com/repo stable main
deb [trusted=yes] http://internal/repo testing main contrib
# bogus line
`)
	got := ParseAPTSourcesList(body, "/etc/apt/sources.list")
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4: %+v", len(got), got)
	}
	if got[0].URL != "http://archive.ubuntu.com/ubuntu" {
		t.Fatalf("URL=%q", got[0].URL)
	}
	if got[0].Distribution != "jammy" {
		t.Fatalf("dist=%q", got[0].Distribution)
	}
	if len(got[0].Components) != 2 {
		t.Fatalf("components=%v", got[0].Components)
	}
	if !got[1].IsSource {
		t.Fatal("deb-src must flag IsSource")
	}
	if got[2].SignedBy != "/usr/share/keyrings/x.gpg" {
		t.Fatalf("signed_by=%q", got[2].SignedBy)
	}
	if got[3].GPGCheck {
		t.Fatal("trusted=yes must disable gpg_check")
	}
	if !got[3].IsThirdParty {
		t.Fatal("internal repo must flag third-party")
	}
	if got[3].IsHTTPS {
		t.Fatal("plain http must NOT flag is_https")
	}
	for _, r := range got {
		if r.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", r)
		}
	}
}

func TestParseAPTSourcesListIgnoresCommentsAndBlanks(t *testing.T) {
	body := []byte("# all comments\n\n# more\n")
	if got := ParseAPTSourcesList(body, "x"); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestParseAPTDeb822Typical(t *testing.T) {
	body := []byte(`Types: deb
URIs: https://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main contrib
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Enabled: yes

Types: deb deb-src
URIs: http://internal.example.com/repo
Suites: stable
Components: main
Trusted: yes
`)
	got := ParseAPTDeb822(body, "/etc/apt/sources.list.d/debian.sources")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if got[0].URL != "https://deb.debian.org/debian" {
		t.Fatalf("URL=%q", got[0].URL)
	}
	if got[0].Distribution != "bookworm" {
		t.Fatalf("dist=%q", got[0].Distribution)
	}
	if !got[0].GPGCheck {
		t.Fatal("missing Trusted=yes must keep GPGCheck=true")
	}
	if got[1].GPGCheck {
		t.Fatal("Trusted=yes must disable GPGCheck")
	}
	if !got[1].IsSource {
		t.Fatal("Types contains deb-src → IsSource")
	}
	if got[1].IsHTTPS {
		t.Fatal("http URL must NOT be flagged https")
	}
}

// -- yum / dnf parser ------------------------------------------------------

func TestParseYumRepoTypical(t *testing.T) {
	body := []byte(`[updates]
name=Fedora 40 - x86_64 - Updates
metalink=https://mirrors.fedoraproject.org/metalink?repo=updates-f40&arch=x86_64
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-40-primary

[scary-extras]
name=Untrusted external repo
baseurl=http://repo.example.com/el9/$basearch
enabled=1
gpgcheck=0
`)
	got := ParseYumRepo(body, "/etc/yum.repos.d/fedora-updates.repo", EcosystemDNF)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}
	if got[0].Name != "updates" {
		t.Fatalf("name=%q", got[0].Name)
	}
	if got[0].URL == "" {
		t.Fatal("metalink fallback should populate URL")
	}
	if !got[0].GPGCheck {
		t.Fatal("gpgcheck=1 must propagate")
	}
	if got[0].IsThirdParty {
		t.Fatal("fedora metalink must NOT flag third-party")
	}
	if got[1].GPGCheck {
		t.Fatal("gpgcheck=0 must flag GPGCheck=false")
	}
	if got[1].IsHTTPS {
		t.Fatal("plain http URL must NOT flag https")
	}
	if !got[1].IsThirdParty {
		t.Fatal("non-fedora mirror must flag third-party")
	}
}

func TestParseYumRepoDisabledFlag(t *testing.T) {
	body := []byte("[off]\nname=Off\nbaseurl=https://x.example/y\nenabled=0\n")
	got := ParseYumRepo(body, "x", EcosystemDNF)
	if len(got) != 1 || got[0].IsEnabled {
		t.Fatalf("enabled=0 must reset IsEnabled: %+v", got)
	}
}

func TestParseAPKRepositories(t *testing.T) {
	body := []byte(`# main
https://dl-cdn.alpinelinux.org/alpine/v3.20/main
http://dl-cdn.alpinelinux.org/alpine/v3.20/community
@edge https://dl-cdn.alpinelinux.org/alpine/edge/testing
`)
	got := ParseAPKRepositories(body, "/etc/apk/repositories")
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	if !got[0].IsHTTPS {
		t.Fatal("first must be https")
	}
	if got[1].IsHTTPS {
		t.Fatal("second is http")
	}
	if got[2].Name != "edge" {
		t.Fatalf("@tag name=%q", got[2].Name)
	}
}

// -- pip parser ------------------------------------------------------------

func TestParsePipConfigPrimaryAndExtra(t *testing.T) {
	body := []byte(`[global]
index-url = https://internal-mirror.corp/simple
extra-index-url = https://pypi.org/simple http://other-mirror/simple
trusted-host = other-mirror

[install]
ignore-installed = true
`)
	got := ParsePipConfig(body, "/etc/pip.conf", "alice")
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 (primary + 2 extras): %+v", len(got), got)
	}
	primary := got[0]
	if primary.Name != "primary" {
		t.Fatalf("primary name=%q", primary.Name)
	}
	if primary.UserScope != "alice" {
		t.Fatalf("user scope=%q", primary.UserScope)
	}
	if !primary.IsHTTPS {
		t.Fatal("primary must flag is_https")
	}
	// other-mirror is trusted-host → GPGCheck=false.
	var otherMirror Repo
	for _, r := range got {
		if r.URL == "http://other-mirror/simple" {
			otherMirror = r
		}
	}
	if otherMirror.GPGCheck {
		t.Fatal("trusted-host mirror must flag GPGCheck=false")
	}
	if otherMirror.IsHTTPS {
		t.Fatal("http trusted-host must NOT be https")
	}
}

// -- npm parser ------------------------------------------------------------

func TestParseNPMrcDefaultAndScoped(t *testing.T) {
	body := []byte(`registry=https://registry.npmjs.org/
@mycorp:registry=https://npm.corp.test/
//other.example/:_authToken=secret
`)
	got := ParseNPMrc(body, "/home/alice/.npmrc", "alice")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}
	want := map[string]string{
		"default": "https://registry.npmjs.org/",
		"@mycorp": "https://npm.corp.test/",
	}
	got2 := map[string]string{}
	for _, r := range got {
		got2[r.Name] = r.URL
	}
	for k, v := range want {
		if got2[k] != v {
			t.Fatalf("name=%q url=%q (want %q)", k, got2[k], v)
		}
	}
	if got[0].UserScope != "alice" {
		t.Fatalf("user=%q", got[0].UserScope)
	}
}

// -- cargo parser ----------------------------------------------------------

func TestParseCargoConfigCustomRegistry(t *testing.T) {
	body := []byte(`[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"

[source.corp]
registry = "https://crates.corp.test/index"

[net]
git-fetch-with-cli = true
`)
	got := ParseCargoConfig(body, "/home/alice/.cargo/config.toml", "alice")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
	}
	if !names["crates-io"] || !names["corp"] {
		t.Fatalf("missing sources: %v", names)
	}
}

// -- gem parser ------------------------------------------------------------

func TestParseGemrcInlineList(t *testing.T) {
	body := []byte(":sources: [https://rubygems.org, https://gems.corp.test/]\n")
	got := ParseGemrc(body, "/home/alice/.gemrc", "alice")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}
	if got[0].URL != "https://rubygems.org" {
		t.Fatalf("url=%q", got[0].URL)
	}
}

func TestParseGemrcBlockList(t *testing.T) {
	body := []byte(":sources:\n  - https://rubygems.org\n  - https://gems.corp.test/\n")
	got := ParseGemrc(body, "/home/alice/.gemrc", "alice")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}
}

// -- collector end-to-end --------------------------------------------------

func TestFileCollectorWalksAllSources(t *testing.T) {
	tmp := t.TempDir()
	aptList := filepath.Join(tmp, "sources.list")
	aptDir := filepath.Join(tmp, "sources.list.d")
	yumDir := filepath.Join(tmp, "yum.repos.d")
	apkPath := filepath.Join(tmp, "apk-repositories")
	pipConf := filepath.Join(tmp, "pip.conf")

	for _, d := range []string{aptDir, yumDir} {
		must(t, os.MkdirAll(d, 0o755))
	}
	mustWrite(t, aptList, "deb http://archive.ubuntu.com/ubuntu jammy main\n")
	mustWrite(t, filepath.Join(aptDir, "ppa.list"),
		"deb [trusted=yes] http://ppa.example/repo stable main\n")
	mustWrite(t, filepath.Join(aptDir, "debian.sources"),
		"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm\nComponents: main\n")
	mustWrite(t, filepath.Join(yumDir, "fedora.repo"),
		"[updates]\nname=Updates\nbaseurl=https://mirrors.fedoraproject.org/x\nenabled=1\ngpgcheck=1\n")
	mustWrite(t, apkPath, "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n")
	mustWrite(t, pipConf, "[global]\nindex-url=https://pypi.org/simple\n")

	c := &fileCollector{
		aptSourcesList:  aptList,
		aptSourcesDir:   aptDir,
		yumReposDir:     yumDir,
		zyppReposDir:    "/nope",
		apkRepositories: apkPath,
		systemPipConf:   pipConf,
		systemNpmrc:     "/nope",
		userHomes:       nil,
		readFile:        os.ReadFile,
		readDir:         os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 apt main + 1 ppa + 1 deb822 + 1 yum + 1 apk + 1 pip = 6.
	if len(got) != 6 {
		t.Fatalf("want 6, got %d: %+v", len(got), got)
	}

	// Check the third-party + trusted=yes PPA was flagged.
	var ppa Repo
	for _, r := range got {
		if r.URL == "http://ppa.example/repo" {
			ppa = r
		}
	}
	if !ppa.IsThirdParty {
		t.Fatal("PPA must flag third-party")
	}
	if ppa.GPGCheck {
		t.Fatal("trusted=yes must flag gpg_check=false")
	}
	if ppa.IsHTTPS {
		t.Fatal("plain http must NOT flag is_https")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		aptSourcesList:  "/nope",
		aptSourcesDir:   "/nope-dir",
		yumReposDir:     "/nope-dir",
		zyppReposDir:    "/nope-dir",
		apkRepositories: "/nope",
		systemPipConf:   "/nope",
		systemNpmrc:     "/nope",
		userHomes:       nil,
		readFile:        os.ReadFile,
		readDir:         os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortReposDeterministic(t *testing.T) {
	in := []Repo{
		{Ecosystem: EcosystemDNF, Name: "z", URL: "https://x"},
		{Ecosystem: EcosystemAPT, Name: "a", URL: "https://x"},
		{Ecosystem: EcosystemAPT, Name: "a", URL: "https://a"},
	}
	SortRepos(in)
	if in[0].Ecosystem != EcosystemAPT || in[0].URL != "https://a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Ecosystem != EcosystemDNF {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers --------------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
