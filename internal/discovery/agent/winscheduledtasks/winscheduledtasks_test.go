package winscheduledtasks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("<Task/>"))
	b := HashContents([]byte("<Task/>"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsMicrosoftManagedPath(t *testing.T) {
	hit := []string{
		`\Microsoft\Windows\AppID\PolicyConverter`,
		`\Microsoft\Windows\Defrag\ScheduledDefrag`,
		`\Microsoft`,
		`\MICROSOFT\anything`,
	}
	for _, p := range hit {
		if !IsMicrosoftManagedPath(p) {
			t.Fatalf("%q must flag Microsoft-managed", p)
		}
	}
	miss := []string{
		`\Vendor\corp-helper`,
		`\OneDriveStandaloneUpdateTask-S-1-5-21-123`,
		`\evilcorp\implant`,
		``,
	}
	for _, p := range miss {
		if IsMicrosoftManagedPath(p) {
			t.Fatalf("%q must NOT flag Microsoft-managed", p)
		}
	}
}

func TestIsSystemPrincipal(t *testing.T) {
	hit := []string{
		"S-1-5-18",
		"s-1-5-18",
		"LocalSystem",
		"SYSTEM",
		"NT AUTHORITY\\SYSTEM",
		" system ",
	}
	for _, s := range hit {
		if !IsSystemPrincipal(s) {
			t.Fatalf("%q must flag SYSTEM", s)
		}
	}
	miss := []string{
		"S-1-5-19", // LocalService
		"DOMAIN\\admin",
		"alice",
		"",
	}
	for _, s := range miss {
		if IsSystemPrincipal(s) {
			t.Fatalf("%q must NOT flag SYSTEM", s)
		}
	}
}

func TestIsHighestRunLevel(t *testing.T) {
	if !IsHighestRunLevel("HighestAvailable") {
		t.Fatal("HighestAvailable must flag")
	}
	if !IsHighestRunLevel(" highestavailable ") {
		t.Fatal("case+whitespace tolerance")
	}
	for _, s := range []string{"LeastPrivilege", "", "garbage"} {
		if IsHighestRunLevel(s) {
			t.Fatalf("%q must NOT flag", s)
		}
	}
}

func TestIsCommandInWorldWritableDir(t *testing.T) {
	hit := []string{
		`C:\Users\Public\dropper.exe`,
		`"C:\Windows\Temp\implant.exe"`,
		`c:\temp\foo.bat`,
		`%TEMP%\stage.ps1`,
		`%PUBLIC%\go.cmd`,
		`%UserProfile%\AppData\Local\Temp\x.exe`,
	}
	for _, c := range hit {
		if !IsCommandInWorldWritableDir(c) {
			t.Fatalf("%q must flag world-writable", c)
		}
	}
	miss := []string{
		`C:\Program Files\Vendor\helper.exe`,
		`C:\Windows\System32\svchost.exe`,
		`C:\ProgramData\Microsoft\config.dll`,
		``,
	}
	for _, c := range miss {
		if IsCommandInWorldWritableDir(c) {
			t.Fatalf("%q must NOT flag world-writable", c)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"LogonTrigger"}); got != `["LogonTrigger"]` {
		t.Fatalf("got %q", got)
	}
}

func TestEncodeActions(t *testing.T) {
	if EncodeActions(nil) != "[]" {
		t.Fatal("nil")
	}
	got := EncodeActions([]Action{{Kind: "Exec", Command: "C:\\x.exe"}})
	if !strings.Contains(got, `"kind":"Exec"`) {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateThirdPartySystemPersistenceHeadline(t *testing.T) {
	tk := Task{
		TaskPath:        `\evilcorp\implant`,
		PrincipalUserID: "S-1-5-18",
		RunLevel:        "HighestAvailable",
		Triggers:        []string{"LogonTrigger", "BootTrigger"},
		Actions:         []Action{{Kind: "Exec", Command: `C:\Users\Public\stage.exe`}},
		IsHidden:        true,
	}
	AnnotateSecurity(&tk)
	if !tk.RunsAsSystem {
		t.Fatal("SYSTEM SID must flag")
	}
	if tk.IsMicrosoftManaged {
		t.Fatal("\\evilcorp\\ must NOT flag Microsoft")
	}
	if !tk.HasLogonTrigger || !tk.HasBootTrigger {
		t.Fatalf("triggers: %+v", tk)
	}
	if !tk.IsCommandInWorldWritableDir {
		t.Fatal("C:\\Users\\Public command must flag world-writable")
	}
	if !tk.IsThirdPartySystemPersistence {
		t.Fatalf("must flag implant headline: %+v", tk)
	}
}

func TestAnnotateMicrosoftBuiltinNeverFlags(t *testing.T) {
	tk := Task{
		TaskPath:        `\Microsoft\Windows\AppID\PolicyConverter`,
		PrincipalUserID: "S-1-5-18",
		Triggers:        []string{"BootTrigger"},
		IsHidden:        true,
	}
	AnnotateSecurity(&tk)
	if !tk.IsMicrosoftManaged {
		t.Fatal("Microsoft path must flag managed")
	}
	if tk.IsThirdPartySystemPersistence {
		t.Fatal("Microsoft-managed tasks never flag the implant headline")
	}
}

func TestAnnotateNonHiddenDoesNotFlagImplant(t *testing.T) {
	tk := Task{
		TaskPath:        `\vendor\updater`,
		PrincipalUserID: "S-1-5-18",
		Triggers:        []string{"LogonTrigger"},
		IsHidden:        false,
	}
	AnnotateSecurity(&tk)
	if tk.IsThirdPartySystemPersistence {
		t.Fatal("non-hidden third-party SYSTEM task ≠ implant — too noisy")
	}
}

// -- ParseTaskXML typical hardened (Microsoft-shipped) ----------------

func TestParseTaskXMLMicrosoftBuiltin(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Built-in periodic defrag</Description>
    <Date>2018-01-01T12:00:00</Date>
    <URI>\Microsoft\Windows\Defrag\ScheduledDefrag</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2018-01-01T03:00:00</StartBoundary>
      <ScheduleByWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%windir%\System32\defrag.exe</Command>
      <Arguments>-c -h -k -g</Arguments>
    </Exec>
  </Actions>
</Task>`)
	got, err := ParseTaskXML(body, `C:\Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag`,
		`\Microsoft\Windows\Defrag\ScheduledDefrag`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.TaskName != "ScheduledDefrag" {
		t.Fatalf("task_name=%q", got.TaskName)
	}
	if got.Author != "Microsoft Corporation" {
		t.Fatalf("author=%q", got.Author)
	}
	if got.PrincipalUserID != "S-1-5-18" || !got.RunsAsSystem {
		t.Fatalf("system flag: %+v", got)
	}
	if got.RunsAsHighest {
		t.Fatal("LeastPrivilege must NOT flag highest")
	}
	if !got.IsMicrosoftManaged {
		t.Fatal("Defrag must flag Microsoft-managed")
	}
	if got.IsThirdPartySystemPersistence {
		t.Fatal("Microsoft-shipped never flags implant")
	}
	// CalendarTrigger isn't in our boolean set — verify via trigger_count.
	if got.TriggerCount != 1 {
		t.Fatalf("trigger_count=%d", got.TriggerCount)
	}
	if got.ActionCount != 1 || got.Actions[0].Command != `%windir%\System32\defrag.exe` {
		t.Fatalf("action: %+v", got.Actions)
	}
}

// -- ParseTaskXML worst-case (third-party SYSTEM persistence) --------

func TestParseTaskXMLWorstCaseImplant(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>EVILCORP\implant</Author>
    <Date>2026-06-23T12:00:00</Date>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\Public\dropper.exe</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>`)
	got, err := ParseTaskXML(body, `C:\Windows\System32\Tasks\evilcorp\implant`,
		`\evilcorp\implant`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.IsHidden {
		t.Fatal("Hidden=true must propagate")
	}
	if !got.HasLogonTrigger || !got.HasBootTrigger {
		t.Fatalf("triggers: %+v", got)
	}
	if !got.IsCommandInWorldWritableDir {
		t.Fatal("C:\\Users\\Public command must flag world-writable")
	}
	if !got.IsThirdPartySystemPersistence {
		t.Fatalf("must flag implant: %+v", got)
	}
}

// -- ParseTaskXML UTF-16 LE BOM handling -----------------------------

func TestParseTaskXMLUTF16LEBOM(t *testing.T) {
	xml := `<?xml version="1.0"?><Task><Settings><Enabled>true</Enabled></Settings></Task>`
	// Encode to UTF-16 LE with BOM. The fixture is pure ASCII, so
	// every rune fits in one byte after the masked range check.
	utf16 := make([]byte, 0, 2+2*len(xml))
	utf16 = append(utf16, 0xFF, 0xFE)
	for _, r := range xml {
		utf16 = append(utf16, byte(r&0x7F), 0x00)
	}
	got, err := ParseTaskXML(utf16, "x", `\test`)
	if err != nil {
		t.Fatalf("UTF-16 LE parse: %v", err)
	}
	if !got.IsEnabled {
		t.Fatalf("Enabled flag lost: %+v", got)
	}
}

// -- ParseTaskXML empty/malformed error paths -----------------------

func TestParseTaskXMLEmpty(t *testing.T) {
	if _, err := ParseTaskXML(nil, "x", `\x`); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseTaskXMLMalformed(t *testing.T) {
	if _, err := ParseTaskXML([]byte("not xml"), "x", `\x`); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksRecursively(t *testing.T) {
	tmp := t.TempDir()
	microsoftDir := filepath.Join(tmp, "Microsoft", "Windows", "Defrag")
	vendorDir := filepath.Join(tmp, "evilcorp")
	must(t, os.MkdirAll(microsoftDir, 0o755))
	must(t, os.MkdirAll(vendorDir, 0o755))

	microsoftXML := `<?xml version="1.0"?>
<Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Settings><Enabled>true</Enabled></Settings></Task>`
	implantXML := `<?xml version="1.0"?>
<Task>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
  <Actions><Exec><Command>C:\Users\Public\stage.exe</Command></Exec></Actions>
</Task>`
	must(t, os.WriteFile(filepath.Join(microsoftDir, "ScheduledDefrag"), []byte(microsoftXML), 0o644))
	must(t, os.WriteFile(filepath.Join(vendorDir, "implant"), []byte(implantXML), 0o644))
	// Hidden file should be skipped.
	must(t, os.WriteFile(filepath.Join(vendorDir, ".hidden"), []byte(implantXML), 0o644))

	c := &fileCollector{
		root:     tmp,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (skip .hidden), got %d: %+v", len(got), got)
	}

	var defrag, implant Task
	for _, tk := range got {
		switch tk.TaskName {
		case "ScheduledDefrag":
			defrag = tk
		case "implant":
			implant = tk
		}
	}
	if !defrag.IsMicrosoftManaged {
		t.Fatalf("defrag should flag Microsoft: %+v", defrag)
	}
	if !implant.IsThirdPartySystemPersistence {
		t.Fatalf("implant should flag headline: %+v", implant)
	}
}

func TestFileCollectorMissingRootOK(t *testing.T) {
	c := &fileCollector{
		root:     "/nope",
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortTasks ------------------------------------------------------

func TestSortTasksDeterministic(t *testing.T) {
	in := []Task{
		{TaskPath: `\Vendor\z`},
		{TaskPath: `\Microsoft\a`},
		{TaskPath: `\Microsoft\b`},
	}
	SortTasks(in)
	if in[0].TaskPath != `\Microsoft\a` {
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
