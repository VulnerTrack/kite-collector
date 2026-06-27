package winfilezilla

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("<FileZilla3/>"))
	b := HashContents([]byte("<FileZilla3/>"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestProtocolName(t *testing.T) {
	cases := map[int]string{
		0:  "ftp",
		1:  "sftp",
		3:  "ftps-implicit",
		4:  "ftpes-explicit",
		6:  "storj",
		99: "unknown",
	}
	for in, want := range cases {
		if got := ProtocolName(in); got != want {
			t.Fatalf("ProtocolName(%d)=%q want %q", in, got, want)
		}
	}
}

func TestAnnotatePlaintextWorldReadable(t *testing.T) {
	s := Site{LogonType: LogonNormal, FileMode: 0o644}
	AnnotateSecurity(&s)
	if !s.IsPasswordPlaintext {
		t.Fatal("normal logon must flag plaintext")
	}
	if !s.IsWorldReadable || !s.IsCredentialExposureRisk {
		t.Fatalf("0o644 + Normal must flag exposure: %+v", s)
	}
}

func TestAnnotatePlaintext0600Clean(t *testing.T) {
	s := Site{LogonType: LogonNormal, FileMode: 0o600}
	AnnotateSecurity(&s)
	if !s.IsPasswordPlaintext {
		t.Fatal("normal logon must flag plaintext")
	}
	if s.IsCredentialExposureRisk {
		t.Fatal("0o600 + Normal alone is NOT immediate-incident")
	}
}

func TestAnnotateMaster(t *testing.T) {
	s := Site{LogonType: LogonAccount, FileMode: 0o644}
	AnnotateSecurity(&s)
	if !s.IsPasswordProtectedByMaster {
		t.Fatal("LogonAccount must flag master-protected")
	}
	if s.IsPasswordPlaintext {
		t.Fatal("LogonAccount is NOT plaintext")
	}
	if s.IsCredentialExposureRisk {
		t.Fatal("master-protected (PBKDF2) is NOT immediate exposure")
	}
}

func TestAnnotateAnonymous(t *testing.T) {
	s := Site{LogonType: LogonAnonymous, FileMode: 0o644}
	AnnotateSecurity(&s)
	if !s.IsAnonymousLogon {
		t.Fatal("LogonAnonymous must flag")
	}
}

func TestParseSitemanagerTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3>
  <Servers>
    <Server>
      <Host>ftp.example.com</Host>
      <Port>21</Port>
      <Protocol>0</Protocol>
      <User>alice</User>
      <Pass encoding="base64">cGFzc3dvcmQ=</Pass>
      <Logontype>1</Logontype>
      <Name>prod-ftp</Name>
    </Server>
    <Folder>
      <Server>
        <Host>sftp.internal</Host>
        <Port>22</Port>
        <Protocol>1</Protocol>
        <User>bob</User>
        <Pass></Pass>
        <Logontype>4</Logontype>
        <Name>internal-sftp</Name>
      </Server>
    </Folder>
    <Server>
      <Host>anon.example.org</Host>
      <Port>21</Port>
      <Protocol>0</Protocol>
      <Logontype>0</Logontype>
      <Name>anon-site</Name>
    </Server>
  </Servers>
</FileZilla3>`)
	got := ParseSitemanager(body)
	if len(got) != 3 {
		t.Fatalf("rows=%d, want 3: %+v", len(got), got)
	}

	byName := map[string]Site{}
	for _, s := range got {
		byName[s.SiteName] = s
	}

	prod := byName["prod-ftp"]
	if prod.LogonType != LogonNormal || prod.SiteHost != "ftp.example.com" {
		t.Fatalf("prod: %+v", prod)
	}
	if prod.SiteProtocol != "ftp" || prod.SitePort != 21 {
		t.Fatalf("prod proto/port: %+v", prod)
	}
	// "password" base64-decoded is 8 bytes.
	if prod.PasswordLength != 8 {
		t.Fatalf("prod password length=%d want 8", prod.PasswordLength)
	}

	internal := byName["internal-sftp"]
	if internal.LogonType != LogonAccount || internal.SiteProtocol != "sftp" {
		t.Fatalf("internal: %+v", internal)
	}

	anon := byName["anon-site"]
	if anon.LogonType != LogonAnonymous {
		t.Fatalf("anon: %+v", anon)
	}
}

func TestParseSitemanagerMalformedReturnsEmpty(t *testing.T) {
	body := []byte("<<<not xml")
	got := ParseSitemanager(body)
	if len(got) != 0 {
		t.Fatalf("malformed must yield empty, got %+v", got)
	}
}

func TestParseSitemanagerBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<FileZilla3><Servers><Server><Host>h</Host><Logontype>1</Logontype></Server></Servers></FileZilla3>`)...)
	got := ParseSitemanager(body)
	if len(got) != 1 {
		t.Fatalf("BOM must be tolerated: %+v", got)
	}
}

func TestFileCollectorWalksPerUserAndEnv(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's sitemanager: plaintext, world-readable.
	aliceSm := filepath.Join(append([]string{usersBase, "alice"},
		SitemanagerRelComponentsPosix()...)...)
	must(t, os.MkdirAll(filepath.Dir(aliceSm), 0o755))
	must(t, os.WriteFile(aliceSm, []byte(`<FileZilla3><Servers>
<Server><Host>ftp.alice</Host><Port>21</Port><Protocol>0</Protocol>
<User>alice</User><Pass encoding="base64">cGFzcw==</Pass>
<Logontype>1</Logontype><Name>alice-ftp</Name></Server>
</Servers></FileZilla3>`), 0o644))

	// Env-supplied FZ_DATADIR with master-protected site.
	envDir := filepath.Join(tmp, "ci-fz")
	must(t, os.MkdirAll(envDir, 0o755))
	envSm := filepath.Join(envDir, "sitemanager.xml")
	must(t, os.WriteFile(envSm, []byte(`<FileZilla3><Servers>
<Server><Host>sftp.ci</Host><Port>22</Port><Protocol>1</Protocol>
<User>ci</User><Logontype>4</Logontype><Name>ci-sftp</Name></Server>
</Servers></FileZilla3>`), 0o600))

	// Public must be skipped.
	pubSm := filepath.Join(append([]string{usersBase, "Public"},
		SitemanagerRelComponentsPosix()...)...)
	must(t, os.MkdirAll(filepath.Dir(pubSm), 0o755))
	must(t, os.WriteFile(pubSm, []byte(`<FileZilla3><Servers>
<Server><Host>skip</Host><Logontype>1</Logontype><Name>skip</Name></Server>
</Servers></FileZilla3>`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv: func(k string) string {
			if k == "FZ_DATADIR" {
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

	var aliceSite, ciSite Site
	for _, s := range got {
		if s.UserProfile == "alice" {
			aliceSite = s
		}
		if s.FilePath == envSm {
			ciSite = s
		}
	}
	if aliceSite.FilePath == "" {
		t.Fatal("alice site missing")
	}
	if !aliceSite.IsPasswordPlaintext || !aliceSite.IsCredentialExposureRisk {
		t.Fatalf("alice plaintext + world-readable must flag: %+v", aliceSite)
	}
	if ciSite.FilePath == "" {
		t.Fatal("env-supplied site missing — FZ_DATADIR not honoured")
	}
	if !ciSite.IsPasswordProtectedByMaster {
		t.Fatalf("ci LogonAccount must flag master: %+v", ciSite)
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

func TestSortSitesDeterministic(t *testing.T) {
	in := []Site{
		{FilePath: "z", SiteHost: "a", SiteName: "n"},
		{FilePath: "a", SiteHost: "z", SiteName: "n"},
		{FilePath: "a", SiteHost: "a", SiteName: "n"},
	}
	SortSites(in)
	if in[0].FilePath != "a" || in[0].SiteHost != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
