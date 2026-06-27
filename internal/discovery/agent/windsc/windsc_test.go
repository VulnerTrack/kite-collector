package windsc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedMOFKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(MOFCurrent), "current"},
		{string(MOFPending), "pending"},
		{string(MOFPrevious), "previous"},
		{string(MOFMetaConfig), "metaconfig"},
		{string(MOFBackup), "backup"},
		{string(MOFUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("mof_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("instance of Foo\n"))
	b := HashContents([]byte("instance of Foo\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeMOFKind(t *testing.T) {
	cases := map[string]MOFKind{
		"Current.mof":          MOFCurrent,
		"current.mof":          MOFCurrent,
		"Pending.mof":          MOFPending,
		"Previous.mof":         MOFPrevious,
		"Backup.mof":           MOFBackup,
		"MetaConfig.mof":       MOFMetaConfig,
		"MetaConfigPlugin.mof": MOFMetaConfig,
		"Random.mof":           MOFUnknown,
		"":                     MOFUnknown,
	}
	for in, want := range cases {
		if got := NormalizeMOFKind(in); got != want {
			t.Fatalf("NormalizeMOFKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsMicrosoftModuleName(t *testing.T) {
	hit := []string{
		"PSDesiredStateConfiguration",
		"psdesiredstateconfiguration",
		"PSDscResources",
		"xWebAdministration",
		"NetworkingDsc",
	}
	for _, m := range hit {
		if !IsMicrosoftModuleName(m) {
			t.Fatalf("%q must flag Microsoft", m)
		}
	}
	miss := []string{
		"EvilCorpDscResources",
		"CustomCompanyDsc",
		"",
	}
	for _, m := range miss {
		if IsMicrosoftModuleName(m) {
			t.Fatalf("%q must NOT flag Microsoft", m)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMicrosoftPendingResource(t *testing.T) {
	r := Resource{
		MOFKind:    MOFPending,
		ModuleName: "PSDesiredStateConfiguration",
	}
	AnnotateSecurity(&r)
	if !r.IsPendingState {
		t.Fatal("Pending MOF must flag pending state")
	}
	if !r.IsMicrosoftModule {
		t.Fatal("PSDesiredStateConfiguration must flag MS")
	}
	if r.IsThirdPartyModule {
		t.Fatal("MS module must NOT flag third-party")
	}
}

func TestAnnotateThirdPartyResource(t *testing.T) {
	r := Resource{
		MOFKind:    MOFCurrent,
		ModuleName: "CustomCompanyDsc",
	}
	AnnotateSecurity(&r)
	if !r.IsThirdPartyModule {
		t.Fatalf("CustomCompanyDsc must flag third-party: %+v", r)
	}
	if r.IsPendingState {
		t.Fatal("Current MOF must NOT flag pending")
	}
}

func TestAnnotateNoModuleNameSkipsThirdPartyFlag(t *testing.T) {
	r := Resource{
		MOFKind:    MOFCurrent,
		ModuleName: "",
	}
	AnnotateSecurity(&r)
	if r.IsMicrosoftModule || r.IsThirdPartyModule {
		t.Fatal("empty module name must clear both module flags")
	}
}

func TestAnnotateMetaConfigFlag(t *testing.T) {
	r := Resource{MOFKind: MOFMetaConfig}
	AnnotateSecurity(&r)
	if !r.IsMetaConfig {
		t.Fatal("MetaConfig MOF must flag is_meta_config")
	}
}

func TestAnnotateAutoCorrectAlreadySet(t *testing.T) {
	// AutoCorrect is set by the parser when it sees
	// ConfigurationMode=ApplyAndAutoCorrect; AnnotateSecurity
	// must NOT clobber it.
	r := Resource{MOFKind: MOFMetaConfig, IsAutoCorrectMode: true}
	AnnotateSecurity(&r)
	if !r.IsAutoCorrectMode {
		t.Fatal("AnnotateSecurity must NOT clear IsAutoCorrectMode")
	}
}

// -- ParseMOF end-to-end ---------------------------------------------

func TestParseMOFTypicalConfiguration(t *testing.T) {
	body := []byte(`/*
@TargetNode='HOST01'
@GeneratedBy=admin
*/
instance of MSFT_FileDirectoryConfiguration as $MSFT_FileDirectoryConfiguration1ref
{
 ResourceID = "[File]EnsureFooExists";
 SourceInfo = "C:\\path\\config.ps1::15::3";
 Type = "Directory";
 DestinationPath = "C:\\Foo";
 ModuleName = "PSDesiredStateConfiguration";
 ModuleVersion = "1.1";
 ConfigurationName = "MyConfig";
};

instance of EvilCorp_RogueService as $rogue1
{
 ResourceID = "[Service]Rogue";
 ModuleName = "EvilCorpDscResources";
 ModuleVersion = "1.0";
 ConfigurationName = "MyConfig";
};

instance of OMI_ConfigurationDocument
{
 Version = "2.0.0";
 Name = "MyConfig";
};
`)
	got := ParseMOF(body, "/etc/Current.mof", MOFCurrent)
	if len(got) != 3 {
		t.Fatalf("rows=%d, want 3: %+v", len(got), got)
	}

	// Row 1 — File resource, Microsoft module.
	if got[0].InstanceType != "MSFT_FileDirectoryConfiguration" {
		t.Fatalf("row 0 type=%q", got[0].InstanceType)
	}
	if got[0].ResourceID != "[File]EnsureFooExists" {
		t.Fatalf("row 0 resource_id=%q", got[0].ResourceID)
	}
	if !got[0].IsMicrosoftModule {
		t.Fatalf("row 0 must flag Microsoft: %+v", got[0])
	}
	if got[0].SourceInfo != `C:\path\config.ps1::15::3` {
		t.Fatalf("row 0 source_info=%q (escape handling wrong)", got[0].SourceInfo)
	}

	// Row 2 — EvilCorp module, third-party.
	if !got[1].IsThirdPartyModule {
		t.Fatalf("row 1 must flag third-party: %+v", got[1])
	}

	// Row 3 — OMI_ConfigurationDocument, no module name.
	if got[2].InstanceType != "OMI_ConfigurationDocument" {
		t.Fatalf("row 2 type=%q", got[2].InstanceType)
	}
	if got[2].IsMicrosoftModule || got[2].IsThirdPartyModule {
		t.Fatal("no module name → both flags cleared")
	}
}

func TestParseMOFMetaConfigAutoCorrect(t *testing.T) {
	body := []byte(`instance of MSFT_DSCMetaConfiguration as $MetaConfig
{
 ConfigurationMode = "ApplyAndAutoCorrect";
 RefreshMode = "Push";
};
`)
	got := ParseMOF(body, "/etc/MetaConfig.mof", MOFMetaConfig)
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if !got[0].IsAutoCorrectMode {
		t.Fatalf("ApplyAndAutoCorrect must flag: %+v", got[0])
	}
	if !got[0].IsMetaConfig {
		t.Fatal("MetaConfig MOF must flag is_meta_config")
	}
}

func TestParseMOFCommentsSkipped(t *testing.T) {
	body := []byte(`// top
# also a comment
instance of Foo
{
 ResourceID = "[X]a";
};
`)
	got := ParseMOF(body, "x", MOFCurrent)
	if len(got) != 1 {
		t.Fatalf("comments broke parser: %d rows", len(got))
	}
}

func TestParseMOFHonoursMaxResources(t *testing.T) {
	var body []byte
	for i := 0; i < MaxResources+10; i++ {
		body = append(body, []byte("instance of Foo\n{\n ResourceID = \"[X]y\";\n};\n")...)
	}
	got := ParseMOF(body, "x", MOFCurrent)
	if len(got) > MaxResources {
		t.Fatalf("got %d > MaxResources %d", len(got), MaxResources)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksMOFs(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.WriteFile(filepath.Join(tmp, "Current.mof"), []byte(`instance of MSFT_File
{
 ResourceID = "[File]a";
 ModuleName = "PSDesiredStateConfiguration";
};
`), 0o644))
	must(t, os.WriteFile(filepath.Join(tmp, "Pending.mof"), []byte(`instance of MSFT_Reg
{
 ResourceID = "[Registry]b";
 ModuleName = "PSDesiredStateConfiguration";
};
`), 0o644))
	must(t, os.WriteFile(filepath.Join(tmp, "MetaConfig.mof"), []byte(`instance of MSFT_DSCMetaConfiguration
{
 ConfigurationMode = "ApplyAndAutoCorrect";
};
`), 0o644))
	// Non-MOF file — must be skipped.
	must(t, os.WriteFile(filepath.Join(tmp, "README.txt"), []byte("skip"), 0o644))

	c := &fileCollector{
		root:     tmp,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	byKind := map[MOFKind]Resource{}
	for _, r := range got {
		byKind[r.MOFKind] = r
	}
	if !byKind[MOFPending].IsPendingState {
		t.Fatal("Pending row must flag pending")
	}
	if !byKind[MOFCurrent].IsMicrosoftModule {
		t.Fatal("Current row must flag MS module")
	}
	if !byKind[MOFMetaConfig].IsAutoCorrectMode {
		t.Fatal("MetaConfig row must flag auto-correct")
	}
}

func TestFileCollectorMissingRootOK(t *testing.T) {
	c := &fileCollector{
		root:     "/nope-dsc",
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

// -- SortResources --------------------------------------------------

func TestSortResourcesDeterministic(t *testing.T) {
	in := []Resource{
		{FilePath: "z", ResourceID: "a"},
		{FilePath: "a", ResourceID: "z"},
		{FilePath: "a", ResourceID: "a"},
	}
	SortResources(in)
	if in[0].FilePath != "a" || in[0].ResourceID != "a" {
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
