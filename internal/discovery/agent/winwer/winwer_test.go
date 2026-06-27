package winwer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedReportKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindArchive), "archive"},
		{string(KindQueue), "queue"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("report_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("wer-body"))
	b := HashContents([]byte("wer-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsLSASSName(t *testing.T) {
	hit := []string{
		"lsass.exe",
		"LSASS.EXE",
		`C:\Windows\System32\lsass.exe`,
		`C:/Windows/System32/lsass.EXE`,
	}
	for _, s := range hit {
		if !IsLSASSName(s) {
			t.Fatalf("%q must flag lsass", s)
		}
	}
	miss := []string{
		"lsa.exe",
		"lsass-svc.exe",
		"chrome.exe",
		"",
	}
	for _, s := range miss {
		if IsLSASSName(s) {
			t.Fatalf("%q must NOT flag lsass", s)
		}
	}
}

func TestIsSecurityProcessName(t *testing.T) {
	hit := []string{"winlogon.exe", "WINLOGON.EXE", "wininit.exe", "svchost.exe", `C:\Windows\System32\services.exe`}
	for _, s := range hit {
		if !IsSecurityProcessName(s) {
			t.Fatalf("%q must flag security process", s)
		}
	}
	miss := []string{"notepad.exe", "calc.exe", "lsass.exe", "", "chrome.exe"}
	for _, s := range miss {
		if IsSecurityProcessName(s) {
			t.Fatalf("%q must NOT flag security process", s)
		}
	}
}

func TestIsBrowserProcessName(t *testing.T) {
	for _, s := range []string{"chrome.exe", "MSEDGE.EXE", "firefox.exe", "brave.exe"} {
		if !IsBrowserProcessName(s) {
			t.Fatalf("%q must flag browser", s)
		}
	}
	for _, s := range []string{"notepad.exe", "lsass.exe", "", "edge.exe"} {
		if IsBrowserProcessName(s) {
			t.Fatalf("%q must NOT flag browser", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateLSASSDumpHeadline(t *testing.T) {
	r := Report{
		AppName:            "lsass.exe",
		MinidumpCount:      1,
		MinidumpTotalBytes: 100 * 1024 * 1024,
	}
	AnnotateSecurity(&r)
	if !r.IsLSASSDump {
		t.Fatal("lsass + minidump must flag LSASS dump")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("LSASS dump must flag credential exposure risk")
	}
	if !r.IsLargeMinidump {
		t.Fatal("100MB must flag large minidump")
	}
}

func TestAnnotateNoMinidumpClearsLSASSFlag(t *testing.T) {
	// Crash event for lsass.exe without an actual .dmp file is
	// less alarming — just metadata, no cred-leak payload.
	r := Report{
		AppName:       "lsass.exe",
		MinidumpCount: 0,
	}
	AnnotateSecurity(&r)
	if r.IsLSASSDump {
		t.Fatal("no minidump → must NOT flag LSASS dump")
	}
}

func TestAnnotateAppPathFallbackForAppName(t *testing.T) {
	r := Report{
		AppPath:       `C:\Windows\System32\lsass.exe`,
		MinidumpCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.IsLSASSDump {
		t.Fatal("AppPath fallback must drive LSASS detection")
	}
}

func TestAnnotateBrowserDump(t *testing.T) {
	r := Report{
		AppName:       "chrome.exe",
		MinidumpCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.IsBrowserDump {
		t.Fatal("chrome.exe minidump must flag browser dump")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("browser dump must flag credential exposure risk")
	}
}

func TestAnnotateNotepadIsClean(t *testing.T) {
	r := Report{
		AppName:       "notepad.exe",
		MinidumpCount: 1,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("notepad dump should NOT flag credential risk")
	}
}

func TestAnnotateLargeMinidumpThreshold(t *testing.T) {
	r := Report{MinidumpCount: 1, MinidumpTotalBytes: LargeMinidumpThresholdBytes}
	AnnotateSecurity(&r)
	if !r.IsLargeMinidump {
		t.Fatal("at-threshold must flag large")
	}

	r2 := Report{MinidumpCount: 1, MinidumpTotalBytes: LargeMinidumpThresholdBytes - 1}
	AnnotateSecurity(&r2)
	if r2.IsLargeMinidump {
		t.Fatal("below-threshold must NOT flag large")
	}
}

// -- ParseReportDescriptor ------------------------------------------

func TestParseReportDescriptorTypicalLSASS(t *testing.T) {
	body := []byte(`EventType=APPCRASH
EventTime=132589123456789012
Consent=1
AppPath=C:\Windows\System32\lsass.exe
Sig[0].Name=Application Name
Sig[0].Value=lsass.exe
Sig[1].Name=Application Version
Sig[1].Value=10.0.19041.844
Sig[2].Name=Fault Module Name
Sig[2].Value=ntdll.dll
Sig[3].Name=Fault Module Version
Sig[3].Value=10.0.19041.844
`)
	var r Report
	ParseReportDescriptor(body, &r)
	if r.EventName != "APPCRASH" {
		t.Fatalf("event=%q", r.EventName)
	}
	if r.AppName != "lsass.exe" {
		t.Fatalf("app=%q", r.AppName)
	}
	if r.AppPath != `C:\Windows\System32\lsass.exe` {
		t.Fatalf("app_path=%q", r.AppPath)
	}
	if r.AppVersion != "10.0.19041.844" {
		t.Fatalf("ver=%q", r.AppVersion)
	}
	if r.FaultModuleName != "ntdll.dll" {
		t.Fatalf("fault=%q", r.FaultModuleName)
	}
	if r.EventTime == 0 {
		t.Fatal("event_time should decode")
	}
	if r.ReportDescriptorHash == "" {
		t.Fatal("descriptor hash must be set")
	}
}

func TestParseReportDescriptorUTF16LE(t *testing.T) {
	// Encode ASCII source as UTF-16 LE + BOM.
	src := "EventType=APPCRASH\r\nAppPath=C:\\Windows\\notepad.exe\r\n"
	body := make([]byte, 0, 2+2*len(src))
	body = append(body, 0xFF, 0xFE)
	for _, c := range src {
		// The fixture is pure ASCII so every rune fits in one byte.
		body = append(body, byte(c&0x7F), 0x00)
	}
	var r Report
	ParseReportDescriptor(body, &r)
	if r.EventName != "APPCRASH" {
		t.Fatalf("UTF-16 event=%q", r.EventName)
	}
	if r.AppPath != `C:\Windows\notepad.exe` {
		t.Fatalf("UTF-16 app_path=%q", r.AppPath)
	}
}

func TestParseReportDescriptorEmptyIsNoop(t *testing.T) {
	r := Report{AppName: "untouched"}
	ParseReportDescriptor(nil, &r)
	if r.AppName != "untouched" {
		t.Fatal("empty body must not touch the row")
	}
	if r.ReportDescriptorHash != "" {
		t.Fatal("empty body must not set descriptor hash")
	}
}

func TestParseReportDescriptorFileTimeMath(t *testing.T) {
	// FILETIME for 2020-01-01T00:00:00Z = 132223104000000000.
	// Unix epoch for that moment is 1577836800.
	body := []byte("EventTime=132223104000000000\n")
	var r Report
	ParseReportDescriptor(body, &r)
	if r.EventTime != 1577836800 {
		t.Fatalf("FILETIME→unix=%d, want 1577836800", r.EventTime)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksArchiveAndQueue(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "ReportArchive")
	queue := filepath.Join(tmp, "ReportQueue")
	must(t, os.MkdirAll(archive, 0o755))
	must(t, os.MkdirAll(queue, 0o755))

	// archive\AppCrash_lsass_x_y\Report.wer + minidump.
	lsassDir := filepath.Join(archive, "AppCrash_lsass_x_y")
	must(t, os.MkdirAll(lsassDir, 0o755))
	must(t, os.WriteFile(filepath.Join(lsassDir, "Report.wer"), []byte(`EventType=APPCRASH
AppPath=C:\Windows\System32\lsass.exe
Sig[0].Name=Application Name
Sig[0].Value=lsass.exe
`), 0o644))
	must(t, os.WriteFile(filepath.Join(lsassDir, "memory.hdmp"),
		[]byte(strings.Repeat("x", 1024)), 0o644))

	// queue\AppCrash_notepad — clean app, no cred-risk.
	notepadDir := filepath.Join(queue, "AppCrash_notepad")
	must(t, os.MkdirAll(notepadDir, 0o755))
	must(t, os.WriteFile(filepath.Join(notepadDir, "Report.wer"), []byte(`EventType=APPCRASH
AppPath=C:\Windows\System32\notepad.exe
Sig[0].Name=Application Name
Sig[0].Value=notepad.exe
`), 0o644))
	must(t, os.WriteFile(filepath.Join(notepadDir, "memory.mdmp"),
		[]byte("dmp"), 0o644))

	// archive\.hidden — must be skipped.
	must(t, os.MkdirAll(filepath.Join(archive, ".hidden"), 0o755))

	c := &fileCollector{
		roots: []rootSeed{
			{path: archive, kind: KindArchive},
			{path: queue, kind: KindQueue},
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
		t.Fatalf("want 2 rows (skip .hidden), got %d: %+v", len(got), got)
	}

	byKind := map[ReportKind]Report{}
	for _, r := range got {
		byKind[r.ReportKind] = r
	}

	arch := byKind[KindArchive]
	if !arch.IsLSASSDump || !arch.IsCredentialExposureRisk {
		t.Fatalf("archive lsass row wrong: %+v", arch)
	}
	if arch.MinidumpTotalBytes != 1024 {
		t.Fatalf("hdmp size not tallied: %+v", arch)
	}

	q := byKind[KindQueue]
	if q.IsLSASSDump || q.IsCredentialExposureRisk {
		t.Fatalf("notepad must NOT flag credential risk: %+v", q)
	}
	if q.MinidumpCount != 1 {
		t.Fatalf("mdmp count wrong: %+v", q)
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots: []rootSeed{
			{path: "/nope-archive", kind: KindArchive},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortReports ----------------------------------------------------

func TestSortReportsDeterministic(t *testing.T) {
	in := []Report{
		{ReportDir: `C:\WER\B`},
		{ReportDir: `C:\WER\A`},
	}
	SortReports(in)
	if in[0].ReportDir != `C:\WER\A` {
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
