package linuxdpkginventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindDpkgStatus), "dpkg-status"},
		{string(KindDpkgCopyright), "dpkg-copyright"},
		{string(KindDpkgList), "dpkg-list"},
		{string(KindAptHistoryLog), "apt-history-log"},
		{string(KindAptTermLog), "apt-term-log"},
		{string(KindDpkgLog), "dpkg-log"},
		{string(KindDebPackageList), "deb-package-list"},
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
		"status",
		"history.log",
		"history.log.1",
		"term.log",
		"dpkg.log",
		"openssl.copyright",
		"openssl.list",
		"firefox.md5sums",
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
		"/var/lib/dpkg/status":                 KindDpkgStatus,
		"/var/lib/dpkg/info/openssl.copyright": KindDpkgCopyright,
		"/var/lib/dpkg/info/openssl.list":      KindDpkgList,
		"/var/log/apt/history.log":             KindAptHistoryLog,
		"/var/log/apt/history.log.2.gz":        KindAptHistoryLog,
		"/var/log/apt/term.log":                KindAptTermLog,
		"/var/log/dpkg.log":                    KindDpkgLog,
		"/var/log/dpkg.log.1":                  KindDpkgLog,
		"/etc/apt/sources.list":                KindDebPackageList,
		"/random.bin":                          KindOther,
		"":                                     KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCountPackages(t *testing.T) {
	body := []byte(`Package: openssl
Status: install ok installed
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
Version: 3.0.11-1
Description: SSL toolkit

Package: firefox
Status: install ok installed
Maintainer: Ubuntu Mozilla Team <ubuntu-mozillateam@lists.ubuntu.com>
Version: 120.0.1
Description: Web browser

Package: postgresql
Status: install ok installed
Maintainer: Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>
Version: 15.4-0
Description: Object-relational database
`)
	if got := CountPackages(body); got != 3 {
		t.Fatalf("CountPackages=%d want 3", got)
	}
}

func TestMaintainerSplit(t *testing.T) {
	body := []byte(`Package: openssl
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.debian.org>

Package: firefox
Maintainer: Ubuntu Mozilla Team <ubuntu-mozillateam@lists.ubuntu.com>

Package: corporate-app
Maintainer: ACME Corp Internal <devops@acme.example.com>
`)
	d, tp := MaintainerSplit(body)
	if d != 2 {
		t.Fatalf("debian=%d want 2", d)
	}
	if tp != 1 {
		t.Fatalf("third_party=%d want 1", tp)
	}
}

func TestCountPIIPackages(t *testing.T) {
	body := []byte(`Package: firefox
Package: thunderbird
Package: openssl
Package: postgresql
Package: build-essential
Package: vim
`)
	// firefox, thunderbird, postgresql, openssh-client?
	// openssl is NOT in catalogue (cryptography lib, not PII handler).
	// build-essential, vim NOT in catalogue.
	// Actually openssh-client is NOT in the test fixture.
	// So expected: firefox + thunderbird + postgresql = 3.
	got := CountPIIPackages(body)
	if got != 3 {
		t.Fatalf("CountPIIPackages=%d want 3 (firefox/thunderbird/postgresql): body=%q", got, string(body))
	}
}

func TestCountDevPackages(t *testing.T) {
	body := []byte(`Package: libssl-dev
Package: linux-headers-amd64
Package: gcc-12-devel
Package: firefox
Package: openssl
`)
	got := CountDevPackages(body)
	if got != 3 {
		t.Fatalf("CountDevPackages=%d want 3 (libssl-dev/linux-headers/gcc-devel)", got)
	}
}

func TestAptInstallStats(t *testing.T) {
	body := []byte(`Start-Date: 2026-06-15  10:30:45
Commandline: apt install firefox
Install: firefox:amd64 (120.0.1)
End-Date: 2026-06-15  10:30:48

Start-Date: 2026-05-01  09:00:00
Commandline: apt upgrade
Upgrade: openssl:amd64 (3.0.10, 3.0.11)
End-Date: 2026-05-01  09:00:05

Start-Date: 2026-06-10  14:22:00
Commandline: apt install postgresql
Install: postgresql:amd64 (15.4)
End-Date: 2026-06-10  14:22:30
`)
	events, earliest, latest := AptInstallStats(body)
	if events != 2 {
		t.Fatalf("events=%d want 2 (only Install: lines)", events)
	}
	if earliest != "20260501" {
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
		ArtifactKind:    KindDpkgStatus,
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

func TestAnnotateThirdPartyExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:              KindDpkgStatus,
		PackageCount:              500,
		ThirdPartyMaintainerCount: 25,
		FileMode:                  0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasThirdPartyRepos {
		t.Fatal("third-party count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + packages + third-party = exposure")
	}
}

func TestAnnotateDevPackages(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindDpkgStatus,
		PackageCount:    500,
		DevPackageCount: 15,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasDevPackages {
		t.Fatal("-dev count > 0 must flag")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindAptHistoryLog,
		LatestInstallYYYYMMDD: "20260601",
		FileMode:              0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("2026-06-01 within 30d of 2026-06-16: %+v", r)
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindAptHistoryLog,
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
		ArtifactKind:    KindDpkgStatus,
		PackageCount:    500,
		PIIPackageCount: 5,
		FileMode:        0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoPackagesNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindDpkgStatus,
		PackageCount:    0,
		PIIPackageCount: 5,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0 packages must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	dpkg := filepath.Join(tmp, "var", "lib", "dpkg")
	must(t, os.MkdirAll(dpkg, 0o755))
	logs := filepath.Join(tmp, "var", "log", "apt")
	must(t, os.MkdirAll(logs, 0o755))

	// dpkg status with PII + third-party + dev packages.
	statusPath := filepath.Join(dpkg, "status")
	must(t, os.WriteFile(statusPath, []byte(`Package: firefox
Status: install ok installed
Maintainer: Ubuntu Mozilla Team <ubuntu-mozillateam@lists.ubuntu.com>
Version: 120.0.1
Description: Web browser
Homepage: https://www.mozilla.org/firefox

Package: postgresql
Status: install ok installed
Maintainer: Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>
Version: 15.4-0
Description: Object-relational database

Package: corporate-app
Status: install ok installed
Maintainer: ACME Corp Internal <devops@acme.example.com>
Version: 1.0.0
Description: Internal corporate tool

Package: libssl-dev
Status: install ok installed
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.debian.org>
Version: 3.0.11-1
Description: SSL toolkit headers
`), 0o644))

	// apt history with recent + old installs, locked down.
	histPath := filepath.Join(logs, "history.log")
	must(t, os.WriteFile(histPath, []byte(`Start-Date: 2026-06-15  10:30:45
Commandline: apt install firefox
Install: firefox:amd64 (120.0.1)
End-Date: 2026-06-15  10:30:48

Start-Date: 2024-01-15  09:00:00
Commandline: apt install postgresql
Install: postgresql:amd64 (15.4)
End-Date: 2024-01-15  09:00:30
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(logs, "random.txt"),
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
	if len(got) != 2 {
		t.Fatalf("want 2 (status+history), got %d: %+v", len(got), got)
	}

	var status, hist Row
	for _, r := range got {
		switch r.FilePath {
		case statusPath:
			status = r
		case histPath:
			hist = r
		}
	}
	if status.ArtifactKind != KindDpkgStatus {
		t.Fatalf("status kind=%q", status.ArtifactKind)
	}
	if status.PackageCount != 4 {
		t.Fatalf("status packages=%d want 4", status.PackageCount)
	}
	if status.DebianMaintainerCount != 3 {
		t.Fatalf("status debian=%d want 3", status.DebianMaintainerCount)
	}
	if status.ThirdPartyMaintainerCount != 1 {
		t.Fatalf("status third-party=%d want 1 (ACME)", status.ThirdPartyMaintainerCount)
	}
	if status.PIIPackageCount < 2 {
		t.Fatalf("status PII=%d want >=2 (firefox/postgresql)", status.PIIPackageCount)
	}
	if status.DevPackageCount != 1 {
		t.Fatalf("status dev=%d want 1 (libssl-dev)", status.DevPackageCount)
	}
	if !status.HasPIIPackages || !status.HasThirdPartyRepos || !status.HasDevPackages {
		t.Fatalf("status flags: %+v", status)
	}
	if !status.IsCredentialExposureRisk {
		t.Fatalf("status readable + packages + PII = exposure: %+v", status)
	}

	if hist.ArtifactKind != KindAptHistoryLog {
		t.Fatalf("hist kind=%q", hist.ArtifactKind)
	}
	if hist.InstallEventCount != 2 {
		t.Fatalf("hist events=%d want 2", hist.InstallEventCount)
	}
	if hist.LatestInstallYYYYMMDD != "20260615" {
		t.Fatalf("hist latest=%q", hist.LatestInstallYYYYMMDD)
	}
	if hist.EarliestInstallYYYYMMDD != "20240115" {
		t.Fatalf("hist earliest=%q", hist.EarliestInstallYYYYMMDD)
	}
	if !hist.HasRecentInstall {
		t.Fatalf("hist must flag recent (2026-06-15): %+v", hist)
	}
	if hist.IsCredentialExposureRisk {
		t.Fatalf("hist 0o600 must NOT flag: %+v", hist)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-dpkg")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "status"),
		[]byte(`Package: firefox
Maintainer: Ubuntu Mozilla Team <ubuntu-mozillateam@lists.ubuntu.com>
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "DPKG_INVENTORY_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindDpkgStatus {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-dpkg"},
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
		{FilePath: "z", ArtifactKind: KindDpkgStatus},
		{FilePath: "a", ArtifactKind: KindAptHistoryLog},
		{FilePath: "a", ArtifactKind: KindDpkgStatus},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAptHistoryLog {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
