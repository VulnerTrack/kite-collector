package wingpo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedGPOScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeMachine), "machine"},
		{string(ScopeUser), "user"},
		{string(ScopePerUser), "per-user"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedArtifactKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindGPTIni), "gpt-ini"},
		{string(KindRegistryPol), "registry-pol"},
		{string(KindScriptStartup), "script-startup"},
		{string(KindScriptShutdown), "script-shutdown"},
		{string(KindScriptLogon), "script-logon"},
		{string(KindScriptLogoff), "script-logoff"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("pol-body"))
	b := HashContents([]byte("pol-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsValidRegistryPol(t *testing.T) {
	good := append([]byte("PReg"), 0x01, 0x00, 0x00, 0x00)
	if !IsValidRegistryPol(good) {
		t.Fatal("canonical PReg header must validate")
	}
	bad := []byte("ABCD\x00\x00\x00\x00")
	if IsValidRegistryPol(bad) {
		t.Fatal("non-PReg header must NOT validate")
	}
	if IsValidRegistryPol(nil) {
		t.Fatal("empty body must NOT validate")
	}
	tooShort := []byte("PReg")
	if IsValidRegistryPol(tooShort) {
		t.Fatal("truncated header must NOT validate")
	}
}

func TestScriptSubdirToKind(t *testing.T) {
	cases := map[string]ArtifactKind{
		"Startup":  KindScriptStartup,
		"startup":  KindScriptStartup,
		"Shutdown": KindScriptShutdown,
		"Logon":    KindScriptLogon,
		"Logoff":   KindScriptLogoff,
		"Random":   KindUnknown,
		"":         KindUnknown,
	}
	for in, want := range cases {
		if got := ScriptSubdirToKind(in); got != want {
			t.Fatalf("ScriptSubdirToKind(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMachineStartupScript(t *testing.T) {
	a := Artifact{GPOScope: ScopeMachine, ArtifactKind: KindScriptStartup}
	AnnotateSecurity(&a)
	if !a.IsMachineScope || !a.IsScriptArtifact {
		t.Fatalf("flags: %+v", a)
	}
	if !a.IsPersistenceCandidate {
		t.Fatal("machine startup script must flag persistence")
	}
}

func TestAnnotatePerUserGPOFlag(t *testing.T) {
	a := Artifact{GPOScope: ScopePerUser, ArtifactKind: KindGPTIni}
	AnnotateSecurity(&a)
	if !a.IsPerUserGPO {
		t.Fatal("per-user scope must flag")
	}
	if !a.IsPersistenceCandidate {
		t.Fatal("per-user GPO is persistence-candidate")
	}
}

func TestAnnotateRegularRegistryPolNotPersistence(t *testing.T) {
	a := Artifact{GPOScope: ScopeMachine, ArtifactKind: KindRegistryPol}
	AnnotateSecurity(&a)
	if a.IsPersistenceCandidate {
		t.Fatal("registry-pol alone is NOT a persistence candidate")
	}
}

// -- ParseGPTIni ----------------------------------------------------

func TestParseGPTIniTypical(t *testing.T) {
	body := []byte(`[General]
gPCMachineExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
Version=131073
displayName=Local Group Policy
`)
	v, ext := ParseGPTIni(body)
	if v != 131073 {
		t.Fatalf("version=%d", v)
	}
	if ext == "" {
		t.Fatal("extension names must be set")
	}
}

func TestParseGPTIniEmptyZeroes(t *testing.T) {
	v, ext := ParseGPTIni(nil)
	if v != 0 || ext != "" {
		t.Fatalf("empty must zero: v=%d ext=%q", v, ext)
	}
}

func TestParseGPTIniBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte("[General]\nVersion=42\n")...)
	v, _ := ParseGPTIni(body)
	if v != 42 {
		t.Fatalf("BOM should be tolerated: v=%d", v)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksLocalAndPerUser(t *testing.T) {
	tmp := t.TempDir()
	local := filepath.Join(tmp, "GroupPolicy")
	perUser := filepath.Join(tmp, "GroupPolicyUsers")
	must(t, os.MkdirAll(filepath.Join(local, "Machine", "Scripts", "Startup"), 0o755))
	must(t, os.MkdirAll(filepath.Join(local, "User"), 0o755))

	// gpt.ini at the local root.
	must(t, os.WriteFile(filepath.Join(local, "gpt.ini"), []byte(`[General]
Version=131073
gPCMachineExtensionNames=[{abcd}]
`), 0o644))

	// Machine Registry.pol (valid signature).
	pol := append([]byte("PReg"), 0x01, 0x00, 0x00, 0x00)
	must(t, os.WriteFile(filepath.Join(local, "Machine", "Registry.pol"), pol, 0o644))

	// Machine\Scripts\Startup\implant.bat — T1037.001 persistence.
	must(t, os.WriteFile(filepath.Join(local, "Machine", "Scripts", "Startup", "implant.bat"),
		[]byte("@echo evil"), 0o644))
	// scripts.ini sibling — should be skipped.
	must(t, os.WriteFile(filepath.Join(local, "Machine", "Scripts", "Startup", "scripts.ini"),
		[]byte("[Startup]\n0CmdLine=implant.bat\n"), 0o644))

	// User Registry.pol with INVALID signature.
	must(t, os.WriteFile(filepath.Join(local, "User", "Registry.pol"),
		[]byte("DEAD\x00\x00\x00\x00"), 0o644))

	// Per-user GPO for SID S-1-5-21-abc with Machine\Registry.pol.
	sidDir := filepath.Join(perUser, "S-1-5-21-1111-2222-3333-1001")
	must(t, os.MkdirAll(filepath.Join(sidDir, "Machine"), 0o755))
	must(t, os.WriteFile(filepath.Join(sidDir, "gpt.ini"), []byte("[General]\nVersion=5\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(sidDir, "Machine", "Registry.pol"), pol, 0o644))

	c := &fileCollector{
		localRoot:   local,
		perUserRoot: perUser,
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Local: gpt.ini + Machine\Registry.pol + Machine\Scripts\Startup\implant.bat + User\Registry.pol = 4.
	// Per-user: gpt.ini + Machine\Registry.pol = 2.
	// scripts.ini skipped. Total = 6.
	if len(got) != 6 {
		t.Fatalf("want 6 rows, got %d: %+v", len(got), got)
	}

	byKind := map[ArtifactKind][]Artifact{}
	for _, a := range got {
		byKind[a.ArtifactKind] = append(byKind[a.ArtifactKind], a)
	}

	if len(byKind[KindGPTIni]) != 2 {
		t.Fatalf("gpt-ini count=%d", len(byKind[KindGPTIni]))
	}
	if len(byKind[KindRegistryPol]) != 3 {
		t.Fatalf("registry-pol count=%d", len(byKind[KindRegistryPol]))
	}
	if len(byKind[KindScriptStartup]) != 1 {
		t.Fatalf("script-startup count=%d", len(byKind[KindScriptStartup]))
	}

	// Verify Machine startup script flagged persistence.
	startup := byKind[KindScriptStartup][0]
	if !startup.IsPersistenceCandidate || !startup.IsMachineScope {
		t.Fatalf("startup script wrong: %+v", startup)
	}

	// Verify per-user GPO Registry.pol flagged per-user.
	var perUserPol Artifact
	for _, p := range byKind[KindRegistryPol] {
		if p.IsPerUserGPO {
			perUserPol = p
		}
	}
	if perUserPol.FilePath == "" {
		t.Fatal("per-user Registry.pol should flag is_per_user_gpo")
	}
	if perUserPol.TargetSID != "S-1-5-21-1111-2222-3333-1001" {
		t.Fatalf("target_sid=%q", perUserPol.TargetSID)
	}
	if !perUserPol.HasPolSignature {
		t.Fatal("valid PReg header must flag has_pol_signature")
	}

	// Verify User\Registry.pol flagged invalid signature.
	var userPol Artifact
	for _, p := range byKind[KindRegistryPol] {
		if p.GPOScope == ScopeUser {
			userPol = p
		}
	}
	if userPol.FilePath == "" {
		t.Fatal("user Registry.pol row missing")
	}
	if !userPol.IsPolSignatureInvalid {
		t.Fatal("DEAD-header pol must flag invalid signature")
	}

	// Verify local gpt.ini parsed.
	var localGPT Artifact
	for _, g := range byKind[KindGPTIni] {
		if g.GPOScope == ScopeMachine {
			localGPT = g
		}
	}
	if localGPT.GPOVersion != 131073 {
		t.Fatalf("local gpt version=%d", localGPT.GPOVersion)
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		localRoot:   "/nope-local",
		perUserRoot: "/nope-peruser",
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortArtifacts --------------------------------------------------

func TestSortArtifactsDeterministic(t *testing.T) {
	in := []Artifact{
		{FilePath: "z"},
		{FilePath: "a"},
	}
	SortArtifacts(in)
	if in[0].FilePath != "a" {
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
