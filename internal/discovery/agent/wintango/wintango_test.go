package wintango

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVendorEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(VendorTango), "tango"},
		{string(VendorBejerman), "bejerman"},
		{string(VendorAxoft), "axoft"},
		{string(VendorAstor), "astor"},
		{string(VendorOther), "other"},
		{string(VendorUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestVendorFromRoot(t *testing.T) {
	roots := DefaultInstallRoots()
	cases := map[string]Vendor{
		`C:\Tango`:    VendorTango,
		`C:\Bejerman`: VendorBejerman,
		`C:\Astor`:    VendorAstor,
		`C:\Axoft`:    VendorAxoft,
		"/opt/tango":  VendorTango,
		"/no/such":    VendorUnknown,
	}
	for in, want := range cases {
		if got := VendorFromRoot(roots, in); got != want {
			t.Fatalf("VendorFromRoot(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"30-71234567-8", "30", "5678"},
		{"30712345678", "30", "5678"},
		{"20_12345678_9", "20", "6789"},
		{"abc", "", ""},
		{"11-12345678-9", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsDataFileExt(t *testing.T) {
	yes := []string{".tdb", ".fpt", ".cdx", ".idx", ".dbf", ".dat", ".mem", ".TDB"}
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

func TestSetModuleFlag(t *testing.T) {
	r := Row{}
	SetModuleFlag(&r, "Sueldos")
	SetModuleFlag(&r, "ventas")
	SetModuleFlag(&r, "TESORERIA")
	SetModuleFlag(&r, "weird-not-real")
	if !r.HasSueldosModule || !r.HasVentasModule || !r.HasTesoreriaModule {
		t.Fatalf("expected flags set: %+v", r)
	}
	if r.HasComprasModule || r.HasContabilidadModule || r.HasStockModule || r.HasActivosModule {
		t.Fatalf("unexpected flags: %+v", r)
	}
}

func TestTruncateDenominacion(t *testing.T) {
	if TruncateDenominacion("ACME S.A.") != "ACME S.A." {
		t.Fatal("short must pass through")
	}
	long := strings.Repeat("a", 200)
	if len(TruncateDenominacion(long)) != MaxDenominationChars {
		t.Fatal("must truncate")
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotateSueldosWorldReadable(t *testing.T) {
	r := Row{DirMode: 0o755, HasSueldosModule: true}
	AnnotateSecurity(&r)
	if !r.IsWorldReadable {
		t.Fatal("0o755 must flag world-readable")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("sueldos + readable must flag exposure")
	}
}

func TestAnnotateTesoreriaGroupReadable(t *testing.T) {
	r := Row{DirMode: 0o750, HasTesoreriaModule: true}
	AnnotateSecurity(&r)
	if !r.IsGroupReadable || r.IsWorldReadable {
		t.Fatalf("0o750 must flag group-only: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("tesoreria + group-readable must flag")
	}
}

func TestAnnotateVentasNoExposure(t *testing.T) {
	r := Row{DirMode: 0o755, HasVentasModule: true}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("ventas alone must NOT flag exposure")
	}
}

func TestAnnotateSueldos0700Clean(t *testing.T) {
	r := Row{DirMode: 0o700, HasSueldosModule: true}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o700 must NOT flag exposure")
	}
}

// -- ParseEmpresaConfig --------------------------------------------

func TestParseEmpresaConfigTypical(t *testing.T) {
	body := []byte(`# Empresa.ini
[empresa]
Denominacion=ACME S.A.
CUIT=30-71234567-8
RazonSocial=ACME Sociedad Anonima
`)
	md := ParseEmpresaConfig(body)
	if md.CuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", md.CuitRaw)
	}
	if md.Denominacion != "ACME S.A." {
		t.Fatalf("denom=%q", md.Denominacion)
	}
}

func TestParseEmpresaConfigQuoted(t *testing.T) {
	body := []byte(`cuit="20-99999999-3"
denominacion='ACME Beta'
`)
	md := ParseEmpresaConfig(body)
	if md.CuitRaw != "20-99999999-3" {
		t.Fatalf("cuit=%q", md.CuitRaw)
	}
	if md.Denominacion != "ACME Beta" {
		t.Fatalf("denom=%q", md.Denominacion)
	}
}

func TestParseEmpresaConfigBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte("CUIT=30712345678\n")...)
	md := ParseEmpresaConfig(body)
	if md.CuitRaw != "30712345678" {
		t.Fatalf("BOM not tolerated: %+v", md)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTango(t *testing.T) {
	tmp := t.TempDir()
	tangoRoot := filepath.Join(tmp, "Tango")
	emp := filepath.Join(tangoRoot, "Empresas")
	must(t, os.MkdirAll(emp, 0o755))

	// ACME with Sueldos + Ventas (multi-tenant pair below).
	acme := filepath.Join(emp, "ACME")
	must(t, os.MkdirAll(filepath.Join(acme, "Sueldos"), 0o755))
	must(t, os.WriteFile(filepath.Join(acme, "Sueldos", "liq.tdb"),
		[]byte("tdb"), 0o644))
	must(t, os.MkdirAll(filepath.Join(acme, "Ventas"), 0o755))
	must(t, os.WriteFile(filepath.Join(acme, "Ventas", "v.fpt"),
		[]byte("fpt"), 0o644))
	must(t, os.WriteFile(filepath.Join(acme, "Empresa.ini"),
		[]byte("CUIT=30-71234567-8\nDenominacion=ACME S.A.\n"), 0o644))

	// BETA with Tesoreria + Contabilidad, dir 0o700.
	beta := filepath.Join(emp, "20-99999999-3")
	must(t, os.MkdirAll(filepath.Join(beta, "Tesoreria"), 0o755))
	must(t, os.WriteFile(filepath.Join(beta, "Tesoreria", "bancos.dbf"),
		[]byte("dbf"), 0o600))
	must(t, os.MkdirAll(filepath.Join(beta, "Contabilidad"), 0o755))
	must(t, os.WriteFile(filepath.Join(beta, "Contabilidad", "cta.tdb"),
		[]byte("tdb"), 0o600))
	must(t, os.Chmod(beta, 0o700))

	c := &fileCollector{
		installRoots: []InstallRoot{{Path: tangoRoot, Vendor: VendorTango}},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (ACME + BETA), got %d: %+v", len(got), got)
	}

	var acmeRow, betaRow Row
	for _, r := range got {
		switch r.EmpresaName {
		case "ACME":
			acmeRow = r
		case "20-99999999-3":
			betaRow = r
		}
	}
	if acmeRow.Vendor != VendorTango {
		t.Fatalf("acme vendor=%q", acmeRow.Vendor)
	}
	if !acmeRow.HasMultipleEmpresas {
		t.Fatal("multi-tenant must flag")
	}
	if !acmeRow.HasSueldosModule || !acmeRow.HasVentasModule {
		t.Fatalf("acme modules: %+v", acmeRow)
	}
	if acmeRow.CuitEntityPrefix != "30" || acmeRow.CuitSuffix4 != "5678" {
		t.Fatalf("acme cuit from ini: %+v", acmeRow)
	}
	if acmeRow.Denominacion != "ACME S.A." {
		t.Fatalf("acme denom=%q", acmeRow.Denominacion)
	}
	if !acmeRow.IsCredentialExposureRisk {
		t.Fatalf("acme sueldos + 0o755 must flag exposure: %+v", acmeRow)
	}

	if betaRow.CuitEntityPrefix != "20" || betaRow.CuitSuffix4 != "9993" {
		t.Fatalf("beta cuit from dir: %+v", betaRow)
	}
	if !betaRow.HasTesoreriaModule || !betaRow.HasContabilidadModule {
		t.Fatalf("beta modules: %+v", betaRow)
	}
	if betaRow.IsCredentialExposureRisk {
		t.Fatalf("beta 0o700 must NOT flag exposure: %+v", betaRow)
	}
}

func TestCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []InstallRoot{{Path: "/nope/tango", Vendor: VendorTango}},
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

func TestCollectorRespectsTangoHomeEnv(t *testing.T) {
	tmp := t.TempDir()
	envRoot := filepath.Join(tmp, "custom-tango")
	must(t, os.MkdirAll(filepath.Join(envRoot, "Empresas", "X", "Stock"), 0o755))
	must(t, os.WriteFile(filepath.Join(envRoot, "Empresas", "X", "Stock", "s.tdb"),
		[]byte("t"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		getenv: func(k string) string {
			if k == "TANGO_HOME" {
				return envRoot
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
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Vendor != VendorTango || !got[0].HasStockModule {
		t.Fatalf("env-root row: %+v", got[0])
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{InstallRoot: "z", Vendor: VendorTango, EmpresaDir: "a"},
		{InstallRoot: "a", Vendor: VendorBejerman, EmpresaDir: "a"},
		{InstallRoot: "a", Vendor: VendorAxoft, EmpresaDir: "a"},
	}
	SortRows(in)
	if in[0].InstallRoot != "a" || in[0].Vendor != VendorAxoft {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestJoinEmpresasPath(t *testing.T) {
	got := JoinEmpresasPath("/r")
	want := filepath.Join("/r", "Empresas")
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
