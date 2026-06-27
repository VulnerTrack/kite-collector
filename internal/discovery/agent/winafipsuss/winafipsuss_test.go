package winafipsuss

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindF931Jubilatoria), "f931-jubilatoria"},
		{string(KindSICOSSAplicativo), "sicoss-aplicativo"},
		{string(KindNominaEmpleados), "nomina-empleados"},
		{string(KindAporteDetalle), "aporte-detalle"},
		{string(KindDDJJObrasocial), "ddjj-obrasocial"},
		{string(KindRelacionLaboral), "relacion-laboral"},
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
		"F931_202506_30712345678.xml",
		"SICOSS_202506.txt",
		"nomina_empleados_202506.csv",
		"sicoss_aporte_202506.csv",
		"ddjj_obrasocial_202506.xml",
		"sicoss_relacion_laboral_001.xml",
		"cargas_sociales_202506.txt",
		"ddjj_sueldos_202506.csv",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.txt"}
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

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"F931_202506_30712345678.xml":     KindF931Jubilatoria,
		"ddjj_obrasocial_202506.xml":      KindDDJJObrasocial,
		"sicoss_relacion_laboral_001.xml": KindRelacionLaboral,
		"sicoss_aporte_202506.csv":        KindAporteDetalle,
		"nomina_empleados_202506.csv":     KindNominaEmpleados,
		"SICOSS_202506.txt":               KindSICOSSAplicativo,
		"cargas_sociales_202506.txt":      KindOther,
		"":                                KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEmpleadorCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"F931_202506_30712345678.xml", "30", "5678"},
		{"juridical 33-22222222-3", "33", "2223"},
		{"natural 27-11111111-4 must be empty", "", ""},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := EmpleadorCuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("Empleador(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestConvenioFromText(t *testing.T) {
	cases := map[string]string{
		"CCT 130/75":             "130/75",
		"convenio colectivo 36":  "36",
		"convenio-colectivo 130": "130",
		"no cct":                 "",
		"":                       "",
	}
	for in, want := range cases {
		if got := ConvenioFromText(in); got != want {
			t.Fatalf("ConvenioFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("F931_202506_30712345678.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateLargePayrollByCount(t *testing.T) {
	r := Row{
		ArtifactKind:        KindF931Jubilatoria,
		EmpleadorCuitPrefix: "30",
		EmpleadosCount:      200,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLargePayroll {
		t.Fatal("200 empleados must flag large")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("empleador + empleados + readable = exposure")
	}
}

func TestAnnotateLargePayrollByTotal(t *testing.T) {
	r := Row{
		ArtifactKind:              KindF931Jubilatoria,
		EmpleadorCuitPrefix:       "30",
		TotalRemuneracionARSCents: 100_000_000_000, // 1B ARS
		FileMode:                  0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLargePayroll {
		t.Fatal("1B ARS total must flag large")
	}
}

func TestAnnotateHighRemuneration(t *testing.T) {
	r := Row{
		ArtifactKind:            KindF931Jubilatoria,
		EmpleadorCuitPrefix:     "30",
		MaxRemuneracionARSCents: 3_000_000_000, // 30 M > 5x 5M MNI = 25M
		FileMode:                0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighRemuneration {
		t.Fatal("30M ARS must flag high remuneration")
	}
}

func TestAnnotateObrasocialData(t *testing.T) {
	r := Row{
		ArtifactKind:         KindF931Jubilatoria,
		EmpleadorCuitPrefix:  "30",
		ObrasocialCodesCount: 5,
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasObrasocialData {
		t.Fatal("obra social codes must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("empleador + obra social + readable = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:        KindF931Jubilatoria,
		EmpleadorCuitPrefix: "30",
		EmpleadosCount:      200,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoEmpleadorNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:   KindF931Jubilatoria,
		EmpleadosCount: 200,
		FileMode:       0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no empleador CUIT must NOT flag exposure")
	}
}

// -- ParseSuss ----------------------------------------------------

func TestParseSussF931XML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<f931>
  <cuit_empleador>30712345678</cuit_empleador>
  <periodo>202506</periodo>
  <convenio_colectivo>130/75</convenio_colectivo>
  <empleado>
    <cuil>20111111119</cuil>
    <remuneracion>1500000.00</remuneracion>
    <obra_social>123201</obra_social>
  </empleado>
  <empleado>
    <cuil>27222222227</cuil>
    <remuneracion>3000000.00</remuneracion>
    <obra_social>123201</obra_social>
  </empleado>
  <empleado>
    <cuil>20333333334</cuil>
    <remuneracion>30000000.00</remuneracion>
    <obra_social>123202</obra_social>
  </empleado>
</f931>`)
	sum, ok := ParseSuss(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.EmpleadorCuitRaw != "30712345678" {
		t.Fatalf("empleador=%q", sum.EmpleadorCuitRaw)
	}
	if sum.ConvenioColectivo != "130/75" {
		t.Fatalf("cct=%q", sum.ConvenioColectivo)
	}
	if sum.EmpleadosCount != 3 {
		t.Fatalf("count=%d", sum.EmpleadosCount)
	}
	if sum.TotalRemuneracionCents != 3_450_000_000 {
		t.Fatalf("total=%d", sum.TotalRemuneracionCents)
	}
	if sum.MaxRemuneracionCents != 3_000_000_000 {
		t.Fatalf("max=%d", sum.MaxRemuneracionCents)
	}
	if sum.ObrasocialCodesCount != 3 {
		t.Fatalf("obrasocial=%d", sum.ObrasocialCodesCount)
	}
}

func TestParseSussCSV(t *testing.T) {
	body := []byte(`cuit_empleador,30712345678
cuil,nombre,remuneracion
20111111119,X,1500000.00
27222222227,Y,3000000.00
`)
	sum, ok := ParseSuss(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.EmpleadorCuitRaw != "30712345678" {
		t.Fatalf("empleador=%q", sum.EmpleadorCuitRaw)
	}
	if sum.EmpleadosCount != 2 {
		t.Fatalf("count=%d", sum.EmpleadosCount)
	}
}

func TestParseSussEmpty(t *testing.T) {
	if _, ok := ParseSuss([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "SICOSS")
	must(t, os.MkdirAll(dir, 0o755))

	// F931 with large payroll, world-readable.
	f931Path := filepath.Join(dir, "F931_202506_30712345678.xml")
	must(t, os.WriteFile(f931Path, []byte(`<?xml version="1.0"?>
<f931>
<cuit_empleador>30712345678</cuit_empleador>
<periodo>202506</periodo>
<empleado><cuil>20111111119</cuil><remuneracion>1500000.00</remuneracion><obra_social>123201</obra_social></empleado>
<empleado><cuil>27222222227</cuil><remuneracion>30000000.00</remuneracion><obra_social>123201</obra_social></empleado>
</f931>`), 0o644))

	// Nomina CSV, locked down.
	nPath := filepath.Join(dir, "nomina_empleados_202506.csv")
	must(t, os.WriteFile(nPath, []byte(`cuit_empleador,30712345678
cuil,nombre,sueldo
20111111119,X,500000.00
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "SICOSS")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "F931_skip.xml"),
		[]byte(`<x/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
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
		t.Fatalf("want 2 (f931+nomina), got %d: %+v", len(got), got)
	}

	var f931, n Row
	for _, r := range got {
		switch r.FilePath {
		case f931Path:
			f931 = r
		case nPath:
			n = r
		}
	}
	if f931.ArtifactKind != KindF931Jubilatoria {
		t.Fatalf("f931 kind=%q", f931.ArtifactKind)
	}
	if f931.EmpleadorCuitPrefix != "30" || f931.EmpleadorCuitSuffix4 != "5678" {
		t.Fatalf("f931 empleador: %+v", f931)
	}
	if f931.EmpleadosCount != 2 {
		t.Fatalf("f931 empleados=%d", f931.EmpleadosCount)
	}
	if !f931.HasHighRemuneration {
		t.Fatalf("30M ARS must flag high: %+v", f931)
	}
	if !f931.HasObrasocialData {
		t.Fatalf("obra social must flag: %+v", f931)
	}
	if !f931.IsCredentialExposureRisk {
		t.Fatalf("empleador + detail + readable = exposure: %+v", f931)
	}

	if n.ArtifactKind != KindNominaEmpleados {
		t.Fatalf("n kind=%q", n.ArtifactKind)
	}
	if n.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", n)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-suss")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "F931_202506.xml"),
		[]byte(`<f931><cuit_empleador>30712345678</cuit_empleador></f931>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SUSS_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindF931Jubilatoria {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-suss"},
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
		{FilePath: "z", ArtifactKind: KindF931Jubilatoria},
		{FilePath: "a", ArtifactKind: KindNominaEmpleados},
		{FilePath: "a", ArtifactKind: KindF931Jubilatoria},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindF931Jubilatoria {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
