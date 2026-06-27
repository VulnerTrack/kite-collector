package linuxrpminventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRPMQAExport), "rpm-qa-export"},
		{string(KindDNFHistoryLog), "dnf-history-log"},
		{string(KindDNFRPMLog), "dnf-rpm-log"},
		{string(KindYumLog), "yum-log"},
		{string(KindRepoConfig), "repo-config"},
		{string(KindRPMDBSQLite), "rpmdb-sqlite"},
		{string(KindRPMDBBerkeley), "rpmdb-berkeley"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"rpm-qa-LAPTOP01.txt",
		"rpm_qa.txt",
		"dnf.log",
		"dnf.log.1",
		"dnf.rpm.log",
		"yum.log",
		"yum.log.2.gz",
		"rpmdb.sqlite",
		"Packages",
		"epel.repo",
		"microsoft-prod.repo",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.bin"}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestArtifactKindFromPath(t *testing.T) {
	cases := map[string]ArtifactKind{
		"/home/admin/rpm-qa-LAPTOP01.txt":      KindRPMQAExport,
		"/var/log/dnf.log":                     KindDNFHistoryLog,
		"/var/log/dnf.log.1":                   KindDNFHistoryLog,
		"/var/log/dnf.rpm.log":                 KindDNFRPMLog,
		"/var/log/yum.log":                     KindYumLog,
		"/var/log/yum.log.2.gz":                KindYumLog,
		"/etc/yum.repos.d/epel.repo":           KindRepoConfig,
		"/etc/dnf/repos.d/microsoft-prod.repo": KindRepoConfig,
		"/var/lib/rpm/rpmdb.sqlite":            KindRPMDBSQLite,
		"/var/lib/rpm/Packages":                KindRPMDBBerkeley,
		"/random.bin":                          KindOther,
		"":                                     KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCountPackagesQA(t *testing.T) {
	body := []byte(`openssl|3.0.7-26.el9|Red Hat, Inc.|https://www.openssl.org/|Cryptography toolkit
firefox|120.0-1.fc41|Fedora Project|https://www.mozilla.org/firefox|Mozilla Firefox
teams|1.6.00.21288|Microsoft Corporation|https://teams.microsoft.com|Microsoft Teams
`)
	if got := CountPackagesQA(body); got != 3 {
		t.Fatalf("CountPackagesQA=%d want 3", got)
	}
}

func TestVendorSplit(t *testing.T) {
	body := []byte(`openssl|3.0.7|Red Hat, Inc.||
firefox|120.0|Fedora Project||
ksh|2020.0|openSUSE||
teams|1.6.00|Microsoft Corporation||
google-chrome|120.0|Google LLC||
acme-internal|1.0|ACME Corp||
`) // each line: NAME|VERSION|VENDOR|URL|SUMMARY (4 pipes)
	redhat, tp := VendorSplit(body)
	if redhat != 3 {
		t.Fatalf("redhat=%d want 3 (Red Hat / Fedora / openSUSE)", redhat)
	}
	if tp != 3 {
		t.Fatalf("third_party=%d want 3 (Microsoft / Google / ACME)", tp)
	}
}

func TestCountPIIPackagesQA(t *testing.T) {
	body := []byte(`firefox|120|||
thunderbird|115|||
postgresql-server|15|||
openssl|3.0.7|||
glibc|2.34|||
`)
	got := CountPIIPackagesQA(body)
	if got != 3 {
		t.Fatalf("CountPIIPackagesQA=%d want 3 (firefox/thunderbird/postgresql-server)", got)
	}
}

func TestCountDevPackagesQA(t *testing.T) {
	body := []byte(`openssl-devel|3.0.7|||
kernel-headers|6.5.0|||
glibc-static|2.34|||
firefox|120|||
openssl|3.0.7|||
`)
	got := CountDevPackagesQA(body)
	if got != 3 {
		t.Fatalf("CountDevPackagesQA=%d want 3 (openssl-devel/kernel-headers/glibc-static)", got)
	}
}

func TestCountRepos(t *testing.T) {
	body := []byte(`[base]
name=Rocky Linux 9 - BaseOS
baseurl=https://mirrors.rockylinux.org/rocky/9/BaseOS/$basearch/os/
enabled=1

[epel]
name=Extra Packages for Enterprise Linux 9
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-9
enabled=1

[microsoft-prod]
name=Microsoft Production
baseurl=https://packages.microsoft.com/rhel/9/prod/
enabled=1
`)
	if got := CountRepos(body); got != 3 {
		t.Fatalf("CountRepos=%d want 3", got)
	}
}

func TestCountThirdPartyRepos(t *testing.T) {
	body := []byte(`[base]
baseurl=https://cdn.redhat.com/content/dist/rhel9/

[epel]
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-9

[centos-extras]
baseurl=https://mirrors.centos.org/extras/

[microsoft-prod]
baseurl=https://packages.microsoft.com/rhel/9/prod/

[google-chrome]
baseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64

[acme-internal]
baseurl=https://repo.acme.example.com/rhel9/
`)
	got := CountThirdPartyRepos(body)
	if got != 3 {
		t.Fatalf("CountThirdPartyRepos=%d want 3 (microsoft/google/acme)", got)
	}
}

func TestDNFInstallStats(t *testing.T) {
	body := []byte(`2026-06-15T10:30:45Z INFO --- logging initialized ---
2026-06-15T10:30:46Z INFO Installed: firefox-0:120.0-1.fc41.x86_64
  Installed: firefox-0:120.0-1.fc41.x86_64
2024-01-15T09:00:00Z INFO Installed: postgresql-server-0:15.4-0.el9.x86_64
  Installed: postgresql-server-0:15.4-0.el9.x86_64
2026-05-01T09:00:00Z INFO Upgraded: openssl-1:3.0.7-26.el9.x86_64
`)
	events, earliest, latest := DNFInstallStats(body)
	if events < 2 {
		t.Fatalf("events=%d want >=2 (Installed: lines)", events)
	}
	if earliest != "20240115" {
		t.Fatalf("earliest=%q", earliest)
	}
	if latest != "20260615" {
		t.Fatalf("latest=%q", latest)
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotatePIIExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindRPMQAExport,
		PackageCount:    500,
		PIIPackageCount: 5,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasPIIPackages {
		t.Fatal("PII count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + packages + PII = exposure")
	}
}

func TestAnnotateThirdPartyVendor(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindRPMQAExport,
		PackageCount:          500,
		ThirdPartyVendorCount: 25,
		FileMode:              0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasThirdPartyRepos {
		t.Fatal("third-party vendor > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + packages + third-party = exposure")
	}
}

func TestAnnotateThirdPartyRepoFile(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindRepoConfig,
		RepoCount:           3,
		ThirdPartyRepoCount: 2,
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasThirdPartyRepos {
		t.Fatal("third-party repo > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + repos + third-party = exposure")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindDNFHistoryLog,
		LatestInstallYYYYMMDD: "20260601",
		FileMode:              0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("2026-06-01 within 30d: %+v", r)
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindDNFHistoryLog,
		LatestInstallYYYYMMDD: "20240101",
		FileMode:              0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindRPMQAExport,
		PackageCount:    500,
		PIIPackageCount: 5,
		FileMode:        0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoContentNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindRPMQAExport,
		PackageCount:    0,
		RepoCount:       0,
		PIIPackageCount: 5,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0 packages + 0 repos must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	homeAdmin := filepath.Join(tmp, "home", "admin")
	must(t, os.MkdirAll(homeAdmin, 0o755))
	logs := filepath.Join(tmp, "var", "log")
	must(t, os.MkdirAll(logs, 0o755))
	repos := filepath.Join(tmp, "etc", "yum.repos.d")
	must(t, os.MkdirAll(repos, 0o755))

	// rpm-qa export with PII + third-party + dev packages,
	// world-readable.
	qaPath := filepath.Join(homeAdmin, "rpm-qa-LAPTOP01.txt")
	must(t, os.WriteFile(qaPath, []byte(`firefox|120.0|Mozilla Foundation|https://mozilla.org|Web browser
postgresql-server|15.4|Red Hat, Inc.|https://www.postgresql.org|PostgreSQL server
teams|1.6.00|Microsoft Corporation|https://teams.microsoft.com|Microsoft Teams
openssl-devel|3.0.7|Red Hat, Inc.|https://www.openssl.org|OpenSSL headers
kernel-headers|6.5.0|Red Hat, Inc.||Linux kernel headers
glibc|2.34|Red Hat, Inc.||GNU C library
`), 0o644))

	// DNF history log with recent + old installs, locked down.
	dnfPath := filepath.Join(logs, "dnf.log")
	must(t, os.WriteFile(dnfPath, []byte(`2026-06-15T10:30:45Z INFO --- logging initialized ---
2026-06-15T10:30:46Z INFO Installed: firefox-0:120.0-1.fc41.x86_64
  Installed: firefox-0:120.0-1.fc41.x86_64
2024-01-15T09:00:00Z INFO Installed: postgresql-server-0:15.4-0.el9.x86_64
  Installed: postgresql-server-0:15.4-0.el9.x86_64
`), 0o600))

	// Repo config with third-party repos, world-readable.
	repoPath := filepath.Join(repos, "vendors.repo")
	must(t, os.WriteFile(repoPath, []byte(`[base]
baseurl=https://cdn.redhat.com/content/dist/rhel9/

[epel]
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-9

[microsoft-prod]
baseurl=https://packages.microsoft.com/rhel/9/prod/

[google-chrome]
baseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(logs, "random.bin"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{tmp},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (qa+dnf+repo), got %d: %+v", len(got), got)
	}

	var qa, dnf, repo Row
	for _, r := range got {
		switch r.FilePath {
		case qaPath:
			qa = r
		case dnfPath:
			dnf = r
		case repoPath:
			repo = r
		}
	}
	if qa.ArtifactKind != KindRPMQAExport {
		t.Fatalf("qa kind=%q", qa.ArtifactKind)
	}
	if qa.PackageCount != 6 {
		t.Fatalf("qa packages=%d want 6", qa.PackageCount)
	}
	if qa.RedHatVendorCount != 4 {
		t.Fatalf("qa redhat=%d want 4", qa.RedHatVendorCount)
	}
	if qa.ThirdPartyVendorCount != 2 {
		t.Fatalf("qa third-party=%d want 2 (Mozilla + Microsoft)", qa.ThirdPartyVendorCount)
	}
	if qa.PIIPackageCount < 2 {
		t.Fatalf("qa PII=%d want >=2 (firefox + postgresql-server)", qa.PIIPackageCount)
	}
	if qa.DevPackageCount != 2 {
		t.Fatalf("qa dev=%d want 2 (openssl-devel + kernel-headers)", qa.DevPackageCount)
	}
	if !qa.HasPIIPackages || !qa.HasThirdPartyRepos || !qa.HasDevPackages {
		t.Fatalf("qa flags: %+v", qa)
	}
	if !qa.IsCredentialExposureRisk {
		t.Fatalf("qa readable + packages + PII = exposure: %+v", qa)
	}

	if dnf.ArtifactKind != KindDNFHistoryLog {
		t.Fatalf("dnf kind=%q", dnf.ArtifactKind)
	}
	if dnf.LatestInstallYYYYMMDD != "20260615" {
		t.Fatalf("dnf latest=%q", dnf.LatestInstallYYYYMMDD)
	}
	if !dnf.HasRecentInstall {
		t.Fatal("dnf must flag recent")
	}
	if dnf.IsCredentialExposureRisk {
		t.Fatalf("dnf 0o600 must NOT flag: %+v", dnf)
	}

	if repo.ArtifactKind != KindRepoConfig {
		t.Fatalf("repo kind=%q", repo.ArtifactKind)
	}
	if repo.RepoCount != 4 {
		t.Fatalf("repo count=%d want 4", repo.RepoCount)
	}
	if repo.ThirdPartyRepoCount != 2 {
		t.Fatalf("repo third-party=%d want 2 (microsoft + google)", repo.ThirdPartyRepoCount)
	}
	if !repo.IsCredentialExposureRisk {
		t.Fatalf("repo readable + repos + third-party = exposure: %+v", repo)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-rpm")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "rpm-qa.txt"),
		[]byte(`firefox|120||||
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "RPM_INVENTORY_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindRPMQAExport {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-rpm"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
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
		{FilePath: "z", ArtifactKind: KindRPMQAExport},
		{FilePath: "a", ArtifactKind: KindDNFHistoryLog},
		{FilePath: "a", ArtifactKind: KindRPMQAExport},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindDNFHistoryLog {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
