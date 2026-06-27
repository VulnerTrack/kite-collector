package winafipsiradig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSIRADIGF572), "siradig-f572"},
		{string(KindF572Monthly), "f572-monthly"},
		{string(KindDependientes), "dependientes"},
		{string(KindAlquiler), "alquiler"},
		{string(KindCreditoHipotecario), "credito-hipotecario"},
		{string(KindGastosMedicos), "gastos-medicos"},
		{string(KindDonaciones), "donaciones"},
		{string(KindGastosEducativos), "gastos-educativos"},
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
		"SIRADIG_27222222227_202506.xml",
		"F572_27222222227_202506.xml",
		"dependientes_siradig_202506.xml",
		"alquiler_siradig_202506.xml",
		"credito_hipotecario_202506.xml",
		"gastos_medicos_siradig_202506.xml",
		"donaciones_siradig_2026.xml",
		"gastos_educativos_siradig_2026.xml",
		"ganancias_4ta_cat_2026.xml",
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
		"dependientes_siradig_202506.xml":    KindDependientes,
		"alquiler_siradig_202506.xml":        KindAlquiler,
		"credito_hipotecario_202506.xml":     KindCreditoHipotecario,
		"gastos_medicos_siradig_202506.xml":  KindGastosMedicos,
		"donaciones_siradig_2026.xml":        KindDonaciones,
		"gastos_educativos_siradig_2026.xml": KindGastosEducativos,
		"F572_27222222227_202506.xml":        KindF572Monthly,
		"SIRADIG_27222222227_202506.xml":     KindSIRADIGF572,
		"ganancias_4ta_cat_2026.xml":         KindOther,
		"":                                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprintEmpleado(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"SIRADIG_27222222227_202506.xml", "27", "2227"},
		{"natural 20-11111111-9", "20", "1119"},
		{"juridical 30-71234567-8 must be empty", "", ""},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintEmpleado(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("Empleado(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCuitFingerprintAny(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"landlord 30-71234567-8", "30", "5678"},
		{"natural 27-22222222-7", "27", "2227"},
		{"invalid 11-12345678-9", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintAny(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("Any(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("SIRADIG_27222222227_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateDependientesExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindDependientes,
		EmpleadoCuitPrefix:  "27",
		EmpleadoCuitSuffix4: "2227",
		DependientesCount:   3,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDependientesPII {
		t.Fatal("dependientes count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("empleado + dependientes + readable = exposure")
	}
}

func TestAnnotateConyuge(t *testing.T) {
	r := Row{
		ArtifactKind:       KindSIRADIGF572,
		EmpleadoCuitPrefix: "27",
		ConyugeCuitPrefix:  "20",
		ConyugeCuitSuffix4: "1119",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if !r.HasConyuge {
		t.Fatal("cónyuge CUIT must flag")
	}
}

func TestAnnotateAlquilerExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindAlquiler,
		EmpleadoCuitPrefix:  "27",
		EmpleadoCuitSuffix4: "2227",
		AlquilerARSCents:    50_000_000,
		LandlordCuitPrefix:  "20",
		LandlordCuitSuffix4: "1119",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAlquiler {
		t.Fatal("alquiler must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("empleado + alquiler + readable = exposure")
	}
}

func TestAnnotateHighDeduction(t *testing.T) {
	r := Row{
		ArtifactKind:             KindSIRADIGF572,
		EmpleadoCuitPrefix:       "27",
		DeduccionesTotalARSCents: 200_000_000, // 2 M ARS > 30% of 5 M MNI
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighDeduction {
		t.Fatal("2 M ARS deducciones must flag high (> 30%% of 5 M MNI)")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("empleado + high-deduction + readable = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindDependientes,
		EmpleadoCuitPrefix: "27",
		DependientesCount:  3,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoEmpleadoNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:      KindDependientes,
		DependientesCount: 3,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no empleado CUIT must NOT flag exposure")
	}
}

// -- ParseSiradig -------------------------------------------------

func TestParseSiradigXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<siradig>
  <cuit_empleado>27222222227</cuit_empleado>
  <cuit_empleador>30712345678</cuit_empleador>
  <cuit_conyuge>20111111119</cuit_conyuge>
  <periodo>202506</periodo>
  <dependiente><nombre>X</nombre></dependiente>
  <dependiente><nombre>Y</nombre></dependiente>
  <cuit_locador>20333333334</cuit_locador>
  <monto_alquiler>500000.00</monto_alquiler>
  <total_deducciones>2000000.00</total_deducciones>
</siradig>`)
	f, ok := ParseSiradig(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.EmpleadoCuitRaw != "27222222227" {
		t.Fatalf("empleado=%q", f.EmpleadoCuitRaw)
	}
	if f.EmpleadorCuitRaw != "30712345678" {
		t.Fatalf("empleador=%q", f.EmpleadorCuitRaw)
	}
	if f.ConyugeCuitRaw != "20111111119" {
		t.Fatalf("conyuge=%q", f.ConyugeCuitRaw)
	}
	if f.LandlordCuitRaw != "20333333334" {
		t.Fatalf("landlord=%q", f.LandlordCuitRaw)
	}
	if f.DependientesCount != 2 {
		t.Fatalf("dependientes=%d", f.DependientesCount)
	}
	if DecimalToCents(f.AlquilerARSText) != 50_000_000 {
		t.Fatalf("alquiler=%d", DecimalToCents(f.AlquilerARSText))
	}
	if DecimalToCents(f.DeduccionesTotalARSText) != 200_000_000 {
		t.Fatalf("deducciones=%d", DecimalToCents(f.DeduccionesTotalARSText))
	}
}

func TestParseSiradigEmpty(t *testing.T) {
	if _, ok := ParseSiradig([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseSiradigNonXML(t *testing.T) {
	if _, ok := ParseSiradig([]byte("cuit,monto\n27,1")); ok {
		t.Fatal("CSV is out-of-scope")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "SIRADIG")
	must(t, os.MkdirAll(dir, 0o755))

	// SIRADIG with dependientes + alquiler, world-readable.
	sPath := filepath.Join(dir, "SIRADIG_27222222227_202506.xml")
	must(t, os.WriteFile(sPath, []byte(`<?xml version="1.0"?>
<siradig>
<cuit_empleado>27222222227</cuit_empleado>
<cuit_empleador>30712345678</cuit_empleador>
<cuit_conyuge>20111111119</cuit_conyuge>
<periodo>202506</periodo>
<dependiente><nombre>X</nombre></dependiente>
<dependiente><nombre>Y</nombre></dependiente>
<cuit_locador>20333333334</cuit_locador>
<monto_alquiler>500000.00</monto_alquiler>
<total_deducciones>2000000.00</total_deducciones>
</siradig>`), 0o644))

	// Dependientes-only file, locked down.
	dPath := filepath.Join(dir, "dependientes_siradig_202506.xml")
	must(t, os.WriteFile(dPath, []byte(`<dependientes>
<cuit_empleado>27222222227</cuit_empleado>
<dependiente><cuit>20999999999</cuit></dependiente>
</dependientes>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "SIRADIG")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "SIRADIG_skip.xml"),
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
		t.Fatalf("want 2 (siradig+dep), got %d: %+v", len(got), got)
	}

	var s, d Row
	for _, r := range got {
		switch r.FilePath {
		case sPath:
			s = r
		case dPath:
			d = r
		}
	}
	if s.ArtifactKind != KindSIRADIGF572 {
		t.Fatalf("s kind=%q", s.ArtifactKind)
	}
	if s.EmpleadoCuitPrefix != "27" || s.EmpleadoCuitSuffix4 != "2227" {
		t.Fatalf("s empleado: %+v", s)
	}
	if s.EmpleadorCuitPrefix != "30" {
		t.Fatalf("s empleador=%q", s.EmpleadorCuitPrefix)
	}
	if s.ConyugeCuitPrefix != "20" {
		t.Fatalf("s conyuge=%q", s.ConyugeCuitPrefix)
	}
	if s.LandlordCuitPrefix != "20" || s.LandlordCuitSuffix4 != "3334" {
		t.Fatalf("s landlord: %+v", s)
	}
	if !s.HasDependientesPII {
		t.Fatal("s dependientes must flag")
	}
	if !s.HasConyuge {
		t.Fatal("s cónyuge must flag")
	}
	if !s.HasAlquiler {
		t.Fatal("s alquiler must flag")
	}
	if !s.HasHighDeduction {
		t.Fatalf("2M ARS must flag high deduction (>30%% of 5M MNI): %+v", s)
	}
	if !s.IsCredentialExposureRisk {
		t.Fatalf("s exposure: %+v", s)
	}

	if d.ArtifactKind != KindDependientes {
		t.Fatalf("d kind=%q", d.ArtifactKind)
	}
	if d.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", d)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-siradig")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "SIRADIG_27222222227_202506.xml"),
		[]byte(`<siradig><cuit_empleado>27222222227</cuit_empleado></siradig>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SIRADIG_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindSIRADIGF572 {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-siradig"},
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
		{FilePath: "z", ArtifactKind: KindSIRADIGF572},
		{FilePath: "a", ArtifactKind: KindDependientes},
		{FilePath: "a", ArtifactKind: KindAlquiler},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAlquiler {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
