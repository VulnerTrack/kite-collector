package winsiap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(CategoryPayroll), "payroll"},
		{string(CategoryIncomeTax), "income-tax"},
		{string(CategoryAutonomos), "autonomos"},
		{string(CategoryConvMultilateral), "conv-multilateral"},
		{string(CategoryBienesPersonales), "bienes-personales"},
		{string(CategoryMisAportes), "mis-aportes"},
		{string(CategoryIVA), "iva"},
		{string(CategoryRetenciones), "retenciones"},
		{string(CategoryOther), "other"},
		{string(CategoryUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestCategoryFromAppName(t *testing.T) {
	cases := map[string]ApplicationCategory{
		"SiAp-F931":             CategoryPayroll,
		"SICOSS":                CategoryPayroll,
		"SueldosLiquidacion":    CategoryPayroll,
		"Ganancias-PF":          CategoryIncomeTax,
		"F572":                  CategoryIncomeTax,
		"GANPF":                 CategoryIncomeTax,
		"Autonomos":             CategoryAutonomos,
		"F184-Autonomos":        CategoryAutonomos,
		"CM05":                  CategoryConvMultilateral,
		"Convenio-Multilateral": CategoryConvMultilateral,
		"Bienes-Personales":     CategoryBienesPersonales,
		"BP-Personas-Fisicas":   CategoryBienesPersonales,
		"Mis_Aportes":           CategoryMisAportes,
		"IVA-General":           CategoryIVA,
		"F2002":                 CategoryIVA,
		"SIREF-Retenciones":     CategoryRetenciones,
		"":                      CategoryUnknown,
		"RandomTool":            CategoryOther,
	}
	for in, want := range cases {
		if got := CategoryFromAppName(in); got != want {
			t.Fatalf("CategoryFromAppName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPayrollAndExposureCategories(t *testing.T) {
	if !IsPayrollCategory(CategoryPayroll) {
		t.Fatal("payroll must be payroll-cat")
	}
	if IsPayrollCategory(CategoryIVA) {
		t.Fatal("IVA must NOT be payroll-cat")
	}
	if !IsExposureCategory(CategoryBienesPersonales) {
		t.Fatal("bienes-personales must be exposure-cat")
	}
	if IsExposureCategory(CategoryConvMultilateral) {
		t.Fatal("conv-multilateral must NOT be exposure-cat")
	}
}

func TestCuitFingerprintFromSubdir(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"30-71234567-8", "30", "5678"},
		{"30712345678", "30", "5678"},
		{"20_12345678_9", "20", "6789"},
		{"Empresa", "", ""},
		{"11-12345678-9", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintFromSubdir(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprintFromSubdir(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsDataFileExt(t *testing.T) {
	yes := []string{".dat", ".dbf", ".cdx", ".idx", ".fpt", ".mem", ".DAT", ".DBF"}
	no := []string{".txt", ".exe", ".ini", "", ".xml"}
	for _, v := range yes {
		if !IsDataFileExt(v) {
			t.Fatalf("expected data ext: %q", v)
		}
	}
	for _, v := range no {
		if IsDataFileExt(v) {
			t.Fatalf("expected NOT data ext: %q", v)
		}
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotatePayrollWorldReadable(t *testing.T) {
	r := Row{ApplicationCategory: CategoryPayroll, DirMode: 0o755}
	AnnotateSecurity(&r)
	if !r.IsPayrollData {
		t.Fatal("payroll cat must flag payroll-data")
	}
	if !r.IsWorldReadable {
		t.Fatal("0o755 must flag world-readable")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("payroll + world-readable must flag exposure")
	}
}

func TestAnnotateIVAReadableNoExposure(t *testing.T) {
	r := Row{ApplicationCategory: CategoryIVA, DirMode: 0o755}
	AnnotateSecurity(&r)
	if r.IsPayrollData {
		t.Fatal("IVA must NOT flag payroll-data")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("IVA + world-readable must NOT escalate")
	}
}

func TestAnnotateBienesPersonalesExposure(t *testing.T) {
	r := Row{ApplicationCategory: CategoryBienesPersonales, DirMode: 0o755}
	AnnotateSecurity(&r)
	if r.IsPayrollData {
		t.Fatal("bienes is NOT payroll")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("bienes + world-readable must flag exposure")
	}
}

func TestAnnotatePayroll0700Clean(t *testing.T) {
	r := Row{ApplicationCategory: CategoryPayroll, DirMode: 0o700}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o700 must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksSIAP(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "S.I.Ap")
	apps := filepath.Join(root, "Aplicaciones")
	must(t, os.MkdirAll(apps, 0o755))

	// F931 with two CUIT subdirs (multi-tenant).
	f931 := filepath.Join(apps, "SiAp-F931")
	must(t, os.MkdirAll(filepath.Join(f931, "30-71234567-8"), 0o755))
	must(t, os.WriteFile(filepath.Join(f931, "30-71234567-8", "F931.dbf"),
		[]byte("dbf"), 0o644))
	must(t, os.WriteFile(filepath.Join(f931, "30-71234567-8", "Empresa.dat"),
		[]byte("dat"), 0o644))
	must(t, os.MkdirAll(filepath.Join(f931, "20-12345678-9"), 0o755))
	must(t, os.WriteFile(filepath.Join(f931, "20-12345678-9", "F931.dbf"),
		[]byte("dbf"), 0o644))

	// IVA with one CUIT subdir, locked down.
	iva := filepath.Join(apps, "IVA-General")
	cuitDir := filepath.Join(iva, "30-99999999-9")
	must(t, os.MkdirAll(cuitDir, 0o700))
	must(t, os.WriteFile(filepath.Join(cuitDir, "iva.dat"), []byte("d"), 0o600))

	// App with no CUIT subdir.
	empty := filepath.Join(apps, "RandomTool")
	must(t, os.MkdirAll(empty, 0o755))

	c := &fileCollector{
		installRoots: []string{root},
		getenv:       func(string) string { return "" },
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// F931 2 rows + IVA 1 row + RandomTool 1 row = 4
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}

	var f931Rows []Row
	var ivaRow, emptyRow Row
	for _, r := range got {
		switch r.ApplicationName {
		case "SiAp-F931":
			f931Rows = append(f931Rows, r)
		case "IVA-General":
			ivaRow = r
		case "RandomTool":
			emptyRow = r
		}
	}
	if len(f931Rows) != 2 {
		t.Fatalf("f931 rows=%d, want 2", len(f931Rows))
	}
	for _, r := range f931Rows {
		if !r.IsLegacySIAP || !r.HasMultipleCuitSubdirs || !r.IsPayrollData {
			t.Fatalf("F931 row: %+v", r)
		}
		if !r.IsCredentialExposureRisk {
			t.Fatalf("F931 0o755 + payroll must flag exposure: %+v", r)
		}
	}
	if ivaRow.ApplicationCategory != CategoryIVA {
		t.Fatalf("IVA cat=%q", ivaRow.ApplicationCategory)
	}
	if ivaRow.HasMultipleCuitSubdirs {
		t.Fatal("IVA single-tenant must NOT flag multi-tenant")
	}
	if ivaRow.IsCredentialExposureRisk {
		t.Fatal("IVA 0o700 must NOT flag exposure")
	}
	if emptyRow.CuitDir != "" {
		t.Fatalf("RandomTool must have empty cuit dir: %+v", emptyRow)
	}
}

func TestCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope/SIAp"},
		getenv:       func(string) string { return "" },
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

func TestCollectorRespectsSIAPHomeEnv(t *testing.T) {
	tmp := t.TempDir()
	envRoot := filepath.Join(tmp, "custom-siap")
	apps := filepath.Join(envRoot, "Aplicaciones", "Mis-Aportes")
	cuit := filepath.Join(apps, "27-11111111-1")
	must(t, os.MkdirAll(cuit, 0o755))
	must(t, os.WriteFile(filepath.Join(cuit, "x.dbf"), []byte("d"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		getenv: func(k string) string {
			if k == "SIAP_HOME" {
				return envRoot
			}
			return ""
		},
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d: %+v", len(got), got)
	}
	if got[0].ApplicationCategory != CategoryMisAportes {
		t.Fatalf("cat=%q", got[0].ApplicationCategory)
	}
}

func TestRecentlyModifiedWindow(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "SIAp")
	cuit := filepath.Join(root, "Aplicaciones", "Old", "30-12345678-2")
	must(t, os.MkdirAll(cuit, 0o755))
	old := filepath.Join(cuit, "stale.dat")
	must(t, os.WriteFile(old, []byte("d"), 0o644))
	// Backdate it 200 days.
	past := time.Now().Add(-200 * 24 * time.Hour)
	must(t, os.Chtimes(old, past, past))

	c := &fileCollector{
		installRoots: []string{root},
		getenv:       func(string) string { return "" },
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, _ := c.Collect(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].IsRecentlyModified {
		t.Fatal("200-day-old file must NOT flag recently-modified")
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{InstallRoot: "z", ApplicationDir: "a", CuitDir: "b"},
		{InstallRoot: "a", ApplicationDir: "b", CuitDir: "c"},
		{InstallRoot: "a", ApplicationDir: "a", CuitDir: "z"},
	}
	SortRows(in)
	if in[0].InstallRoot != "a" || in[0].ApplicationDir != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestJoinAplicacionesPath(t *testing.T) {
	got := JoinAplicacionesPath("/root/SIAp")
	want := filepath.Join("/root/SIAp", "Aplicaciones")
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
