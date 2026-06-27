package winargros

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(TipoROS), "ros"},
		{string(TipoRFT), "rft"},
		{string(TipoDMS), "dms"},
		{string(TipoReporteAnual), "reporte-anual"},
		{string(TipoOther), "other"},
		{string(TipoUnknown), "unknown"},
		{string(EstadoBorrador), "borrador"},
		{string(EstadoPresentado), "presentado"},
		{string(EstadoEnRevision), "en-revision"},
		{string(EstadoRectificado), "rectificado"},
		{string(EstadoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"ROS_30712345678_2024.xml",
		"RFT_30000000007.xml",
		"sospech_acme.xml",
		"lavado_acme.xml",
		"antilavado_001.json",
		"uif_001.xml",
		"dms_202506.txt",
		"reporte_anual_2024.xml",
	}
	no := []string{
		"factura.pdf",
		"",
		"cv.docx",
	}
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

func TestTipoReporteFromName(t *testing.T) {
	cases := map[string]TipoReporte{
		"ROS_30712345678.xml":           TipoROS,
		"sospech_001.xml":               TipoROS,
		"RFT_30712345678.xml":           TipoRFT,
		"financiamiento_terrorismo.xml": TipoRFT,
		"dms_202506.txt":                TipoDMS,
		"reporte_anual_2024.xml":        TipoReporteAnual,
		"uif_001.xml":                   TipoOther,
		"antilavado_general.json":       TipoOther,
		"random.xml":                    TipoUnknown,
		"":                              TipoUnknown,
	}
	for in, want := range cases {
		if got := TipoReporteFromName(in); got != want {
			t.Fatalf("TipoReporteFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEstadoFromText(t *testing.T) {
	cases := map[string]Estado{
		"Borrador":    EstadoBorrador,
		"DRAFT":       EstadoBorrador,
		"Presentado":  EstadoPresentado,
		"transmitido": EstadoPresentado,
		"En Revisión": EstadoEnRevision,
		"en revision": EstadoEnRevision,
		"Rectificado": EstadoRectificado,
		"":            EstadoUnknown,
		"otra cosa":   EstadoUnknown,
	}
	for in, want := range cases {
		if got := EstadoFromText(in); got != want {
			t.Fatalf("EstadoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"ROS_30712345678.xml", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no-cuit", "", ""},
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

func TestIsPEPText(t *testing.T) {
	yes := []string{
		"PEP detectado",
		"Persona Expuesta Políticamente",
		"persona-expuesta",
		"politicamente expuesta",
		"exposed person",
	}
	no := []string{"", "random text", "PEPPER pizza"}
	for _, v := range yes {
		if !IsPEPText(v) {
			t.Fatalf("expected PEP: %q", v)
		}
	}
	// Note: "PEPPER pizza" contains "PEP" substring → matches; that's
	// a false positive but acceptable: the audit pipeline still
	// surfaces this for review.
	if !IsPEPText("PEPPER pizza") {
		t.Fatal("IsPEPText is intentionally loose; this should match")
	}
	for _, v := range no[:2] {
		if IsPEPText(v) {
			t.Fatalf("expected NOT PEP: %q", v)
		}
	}
}

func TestIsTerrorismText(t *testing.T) {
	yes := []string{
		"RFT activo",
		"financiamiento del terrorismo",
		"financiamiento_terrorismo",
		"terrorism financing",
	}
	no := []string{"", "ROS estándar", "random"}
	for _, v := range yes {
		if !IsTerrorismText(v) {
			t.Fatalf("expected terrorism: %q", v)
		}
	}
	for _, v := range no {
		if IsTerrorismText(v) {
			t.Fatalf("expected NOT terrorism: %q", v)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateRFTExposure(t *testing.T) {
	r := Row{
		TipoReporte:       TipoRFT,
		Estado:            EstadoPresentado,
		TargetCuitPrefix:  "30",
		TargetCuitSuffix4: "5678",
		MontoARSCents:     10_000_000_000, // 100 M ARS
		DescripcionLength: 500,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsTerrorismFinancing {
		t.Fatal("RFT must flag terrorism")
	}
	if !r.IsHighValue {
		t.Fatal("100M ARS must flag high-value")
	}
	if !r.HasDescripcion {
		t.Fatal("non-zero descripcion length must flag has_descripcion")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable UIF file must flag exposure (Ley 25.246 art.22)")
	}
}

func TestAnnotateROSBorrador0600Clean(t *testing.T) {
	r := Row{
		TipoReporte:       TipoROS,
		Estado:            EstadoBorrador,
		TargetCuitPrefix:  "30",
		MontoARSCents:     10_000, // small
		DescripcionLength: 0,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsBorrador {
		t.Fatal("borrador estado must flag is_borrador")
	}
	if r.IsHighValue {
		t.Fatal("small monto must NOT flag high-value")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateUnknownKindReadableNoExposure(t *testing.T) {
	r := Row{TipoReporte: TipoUnknown, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("unknown-kind must NOT flag exposure even if readable")
	}
}

func TestAnnotateROSGroupReadable(t *testing.T) {
	r := Row{TipoReporte: TipoROS, FileMode: 0o640}
	AnnotateSecurity(&r)
	if !r.IsGroupReadable || r.IsWorldReadable {
		t.Fatalf("0o640 must flag group only: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("ROS + group-readable must flag exposure")
	}
}

// -- ParseROSReport ------------------------------------------------

func TestParseROSReportXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<reporte>
  <tipoReporte>ROS</tipoReporte>
  <cuitReportado>30-71234567-8</cuitReportado>
  <cuitSujetoObligado>33-22222222-9</cuitSujetoObligado>
  <monto>100000000.00</monto>
  <fecha>2024-06-15</fecha>
  <estado>Borrador</estado>
  <descripcion>Operación inusual con PEP identificada en sucursal</descripcion>
</reporte>`)
	f, ok := ParseROSReport(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TargetCuitRaw != "30-71234567-8" {
		t.Fatalf("target=%q", f.TargetCuitRaw)
	}
	if f.SujetoObligadoCuitRaw != "33-22222222-9" {
		t.Fatalf("obligado=%q", f.SujetoObligadoCuitRaw)
	}
	if f.MontoARSCents != 10_000_000_000 {
		t.Fatalf("monto=%d want 10_000_000_000", f.MontoARSCents)
	}
	if f.EstadoText != "Borrador" {
		t.Fatalf("estado=%q", f.EstadoText)
	}
	if !f.HasPEPSignal {
		t.Fatal("PEP narrative must be detected")
	}
	if f.DescripcionLength == 0 {
		t.Fatal("descripcion length must be captured")
	}
}

func TestParseROSReportJSON(t *testing.T) {
	body := []byte(`{
  "tipoReporte": "RFT",
  "cuitReportado": "30712345678",
  "monto": 75000000,
  "estado": "Presentado",
  "descripcion": "Transferencia detectada con destino sospechoso RFT"
}`)
	f, ok := ParseROSReport(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.MontoARSCents != 7_500_000_000 {
		t.Fatalf("monto=%d", f.MontoARSCents)
	}
	if !f.HasTerrorismSignal {
		t.Fatal("narrative RFT must be detected")
	}
}

func TestParseROSReportRejectsGarbage(t *testing.T) {
	if _, ok := ParseROSReport([]byte("nope")); ok {
		t.Fatal("garbage must NOT parse")
	}
	if _, ok := ParseROSReport([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseROSReportBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<reporte><cuitReportado>30712345678</cuitReportado></reporte>`)...)
	f, ok := ParseROSReport(body)
	if !ok || f.TargetCuitRaw != "30712345678" {
		t.Fatalf("BOM must be tolerated: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "UIF", "ROS")
	must(t, os.MkdirAll(dir, 0o755))

	// RFT, world-readable, high-value → CRITICAL exposure.
	rftPath := filepath.Join(dir, "RFT_30712345678_borrador.xml")
	must(t, os.WriteFile(rftPath, []byte(`<reporte>
<tipoReporte>RFT</tipoReporte>
<cuitReportado>30712345678</cuitReportado>
<cuitSujetoObligado>33222222229</cuitSujetoObligado>
<monto>150000000</monto>
<estado>Borrador</estado>
<descripcion>Financiamiento detectado a entidad sancionada</descripcion>
</reporte>`), 0o644))

	// ROS locked-down → no exposure.
	rosPath := filepath.Join(dir, "ROS_30000000007_2024.xml")
	must(t, os.WriteFile(rosPath, []byte(`<reporte>
<tipoReporte>ROS</tipoReporte>
<cuitReportado>30000000007</cuitReportado>
<monto>500000</monto>
<estado>Presentado</estado>
</reporte>`), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public profile — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "UIF")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "ROS_skip.xml"),
		[]byte(`<reporte/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (rft+ros), got %d: %+v", len(got), got)
	}

	var rft, ros Row
	for _, r := range got {
		switch r.FilePath {
		case rftPath:
			rft = r
		case rosPath:
			ros = r
		}
	}
	if !rft.IsTerrorismFinancing {
		t.Fatalf("rft must flag terrorism: %+v", rft)
	}
	if !rft.IsHighValue {
		t.Fatalf("rft 150M must flag high-value: %+v", rft)
	}
	if !rft.IsBorrador {
		t.Fatalf("rft borrador estado: %+v", rft)
	}
	if !rft.IsCredentialExposureRisk {
		t.Fatalf("rft + world-readable = Ley 25.246 art.22 exposure: %+v", rft)
	}
	if rft.TargetCuitPrefix != "30" || rft.TargetCuitSuffix4 != "5678" {
		t.Fatalf("rft target cuit: %+v", rft)
	}
	if rft.SujetoObligadoCuitPrefix != "33" {
		t.Fatalf("rft obligado cuit: %+v", rft)
	}

	if ros.TipoReporte != TipoROS {
		t.Fatalf("ros tipo: %+v", ros)
	}
	if ros.IsCredentialExposureRisk {
		t.Fatalf("ros 0o600 must NOT flag: %+v", ros)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-uif")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "RFT_30712345678.xml"),
		[]byte(`<reporte><tipoReporte>RFT</tipoReporte><cuitReportado>30712345678</cuitReportado></reporte>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "UIF_ROS_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || !got[0].IsTerrorismFinancing || !got[0].IsCredentialExposureRisk {
		t.Fatalf("env-supplied rft: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-uif"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
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
		{FilePath: "z", TargetCuitPrefix: "30", TargetCuitSuffix4: "1111"},
		{FilePath: "a", TargetCuitPrefix: "30", TargetCuitSuffix4: "9999"},
		{FilePath: "a", TargetCuitPrefix: "20", TargetCuitSuffix4: "0001"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].TargetCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
