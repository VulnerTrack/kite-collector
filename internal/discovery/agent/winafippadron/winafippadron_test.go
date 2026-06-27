package winafippadron

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(QueryPadronA4), "padron-a4"},
		{string(QueryPadronA5), "padron-a5"},
		{string(QueryPadronA10), "padron-a10"},
		{string(QueryPadronA13), "padron-a13"},
		{string(QueryContribOther), "contribuyente-other"},
		{string(QueryUnknown), "unknown"},
		{string(SituacionResponsableInscripto), "responsable-inscripto"},
		{string(SituacionMonotributista), "monotributista"},
		{string(SituacionExento), "exento"},
		{string(SituacionNoAlcanzado), "no-alcanzado"},
		{string(SituacionNoInscripto), "no-inscripto"},
		{string(SituacionUnknown), "unknown"},
		{string(EstadoActivo), "activo"},
		{string(EstadoBaja), "baja"},
		{string(EstadoInactivo), "inactivo"},
		{string(EstadoSuspendido), "suspendido"},
		{string(EstadoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestQueryKindFromName(t *testing.T) {
	cases := map[string]QueryKind{
		"padron_a5_30712345678.xml":     QueryPadronA5,
		"padron-a4-30712345678.json":    QueryPadronA4,
		"ws_sr_padron_a10_resp.xml":     QueryPadronA10,
		"consulta_a13_acme.json":        QueryPadronA13,
		"contribuyente_30712345678.xml": QueryContribOther,
		"consulta_constancia_acme.xml":  QueryContribOther,
		"random.xml":                    QueryUnknown,
		"":                              QueryUnknown,
	}
	for in, want := range cases {
		if got := QueryKindFromName(in); got != want {
			t.Fatalf("QueryKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSituacionFromText(t *testing.T) {
	cases := map[string]SituacionIVA{
		"IVA Responsable Inscripto":  SituacionResponsableInscripto,
		"responsable inscripto":      SituacionResponsableInscripto,
		"Monotributista Categoría A": SituacionMonotributista,
		"MONOTRIBUTISTA":             SituacionMonotributista,
		"Exento":                     SituacionExento,
		"IVA No Alcanzado":           SituacionNoAlcanzado,
		"No Inscripto":               SituacionNoInscripto,
		"":                           SituacionUnknown,
		"Otra cosa":                  SituacionUnknown,
	}
	for in, want := range cases {
		if got := SituacionFromText(in); got != want {
			t.Fatalf("SituacionFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEstadoFromText(t *testing.T) {
	cases := map[string]EstadoCUIT{
		"ACTIVO":     EstadoActivo,
		"BAJA":       EstadoBaja,
		"INACTIVO":   EstadoInactivo,
		"SUSPENDIDO": EstadoSuspendido,
		"activo":     EstadoActivo,
		"":           EstadoUnknown,
	}
	for in, want := range cases {
		if got := EstadoFromText(in); got != want {
			t.Fatalf("EstadoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsRiskyCLAE(t *testing.T) {
	yes := []string{
		"6491", "6492", "6499", "6499xx", "6611", "9200", "9329", "649900",
	}
	no := []string{
		"4711", "1010", "", "abcd",
	}
	for _, v := range yes {
		if !IsRiskyCLAE(v) {
			t.Fatalf("expected risky: %q", v)
		}
	}
	for _, v := range no {
		if IsRiskyCLAE(v) {
			t.Fatalf("expected NOT risky: %q", v)
		}
	}
}

func TestExtractCLAECodes(t *testing.T) {
	// `ab1234` is skipped because \b doesn't sit between `b` and a
	// digit — both are word characters in Go regex.
	in := "actividades: 6499, 1010, 9329, ab1234, 649900"
	got := ExtractCLAECodes(in)
	want := map[string]bool{"6499": true, "1010": true, "9329": true, "649900": true}
	for _, c := range got {
		if !want[c] {
			t.Fatalf("unexpected code: %q (got %v)", c, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("count mismatch: got %v want %v", got, want)
	}
}

func TestTruncateDenominacion(t *testing.T) {
	if TruncateDenominacion("ACME") != "ACME" {
		t.Fatal("short pass-through")
	}
	long := strings.Repeat("á", 200)
	got := TruncateDenominacion(long)
	if len([]rune(got)) != MaxDenominacionChars {
		t.Fatalf("len=%d want %d", len([]rune(got)), MaxDenominacionChars)
	}
}

// -- AnnotateSecurity -----------------------------------------------

func TestAnnotateResponsableExposure(t *testing.T) {
	r := Row{
		SituacionIVA:     SituacionResponsableInscripto,
		EstadoCUIT:       EstadoActivo,
		Denominacion:     "ACME S.A.",
		TargetCuitPrefix: "30",
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsResponsableInscripto {
		t.Fatal("responsable flag must set")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("PII + readable must flag exposure")
	}
}

func TestAnnotateBajaMonotrib(t *testing.T) {
	r := Row{
		SituacionIVA:     SituacionMonotributista,
		EstadoCUIT:       EstadoBaja,
		Denominacion:     "JUAN",
		TargetCuitPrefix: "20",
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsMonotributista || !r.IsBaja {
		t.Fatalf("flags: %+v", r)
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateExentoClean(t *testing.T) {
	r := Row{SituacionIVA: SituacionExento, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsExento {
		t.Fatal("exento flag must set")
	}
}

// -- ParsePadronCache ----------------------------------------------

func TestParsePadronCacheXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<personaReturn>
  <persona>
    <idPersona>30712345678</idPersona>
    <razonSocial>ACME S.A.</razonSocial>
    <estadoClave>ACTIVO</estadoClave>
    <descripcionProvincia>BUENOS AIRES</descripcionProvincia>
    <categoriasMonotributo/>
    <impuestos>
      <impuesto>
        <descripcion>IVA Responsable Inscripto</descripcion>
      </impuesto>
    </impuestos>
    <actividades>
      <actividad>
        <idActividad>649900</idActividad>
      </actividad>
      <actividad>
        <idActividad>620100</idActividad>
      </actividad>
    </actividades>
  </persona>
</personaReturn>`)
	r, ok := ParsePadronCache(body)
	if !ok {
		t.Fatal("must parse")
	}
	if r.TargetCuitPrefix != "30" || r.TargetCuitSuffix4 != "5678" {
		t.Fatalf("cuit: %+v", r)
	}
	if r.Denominacion != "ACME S.A." {
		t.Fatalf("denom=%q", r.Denominacion)
	}
	if r.SituacionIVA != SituacionResponsableInscripto {
		t.Fatalf("situacion=%q", r.SituacionIVA)
	}
	if r.EstadoCUIT != EstadoActivo {
		t.Fatalf("estado=%q", r.EstadoCUIT)
	}
	if r.DomicilioProvincia != "BUENOS AIRES" {
		t.Fatalf("provincia=%q", r.DomicilioProvincia)
	}
	if r.ActividadesCount != 2 || r.PrimaryActividadCLAE != "649900" {
		t.Fatalf("actividades: %+v", r)
	}
	if !r.HasRiskyActividades {
		t.Fatal("649900 must flag risky CLAE")
	}
}

func TestParsePadronCacheJSON(t *testing.T) {
	body := []byte(`{
  "idPersona": "30712345678",
  "razonSocial": "ACME S.A.",
  "estadoClave": "ACTIVO",
  "descripcionProvincia": "CABA",
  "situacionTributaria": "Monotributista",
  "actividades": [
    {"idActividad": "1010"},
    {"idActividad": "9200"}
  ]
}`)
	r, ok := ParsePadronCache(body)
	if !ok {
		t.Fatal("must parse")
	}
	if r.TargetCuitPrefix != "30" || r.TargetCuitSuffix4 != "5678" {
		t.Fatalf("cuit: %+v", r)
	}
	if r.SituacionIVA != SituacionMonotributista {
		t.Fatalf("situacion=%q", r.SituacionIVA)
	}
	if !r.HasRiskyActividades {
		t.Fatal("9200 must flag risky CLAE")
	}
}

func TestParsePadronCacheRejectsGarbage(t *testing.T) {
	if _, ok := ParsePadronCache([]byte("not xml or json")); ok {
		t.Fatal("garbage must NOT parse")
	}
	if _, ok := ParsePadronCache([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	cacheDir := filepath.Join(usersBase, "alice", ".pyafipws", "padron_cache")
	must(t, os.MkdirAll(cacheDir, 0o755))

	// Risky responsable inscripto, world-readable.
	riskyPath := filepath.Join(cacheDir, "padron_a5_30712345678.xml")
	must(t, os.WriteFile(riskyPath, []byte(`<personaReturn><persona>
<idPersona>30712345678</idPersona>
<razonSocial>FINTECH SA</razonSocial>
<estadoClave>ACTIVO</estadoClave>
<impuestos><impuesto><descripcion>IVA Responsable Inscripto</descripcion></impuesto></impuestos>
<actividades><actividad><idActividad>6499</idActividad></actividad></actividades>
</persona></personaReturn>`), 0o644))

	// Locked-down monotributo (no PII exposure).
	monoPath := filepath.Join(cacheDir, "consulta_a13_20111111112.json")
	must(t, os.WriteFile(monoPath, []byte(`{"idPersona":"20111111112","razonSocial":"PEPE","estadoClave":"ACTIVO","situacionTributaria":"Monotributista"}`), 0o600))

	// Public profile must be skipped.
	pubDir := filepath.Join(usersBase, "Public", ".pyafipws", "padron_cache")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "padron_a5_30000000007.xml"),
		[]byte(`<personaReturn><persona><idPersona>30000000007</idPersona></persona></personaReturn>`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (risky + mono), got %d: %+v", len(got), got)
	}

	var risky, mono Row
	for _, r := range got {
		switch r.FilePath {
		case riskyPath:
			risky = r
		case monoPath:
			mono = r
		}
	}
	if risky.FilePath == "" || mono.FilePath == "" {
		t.Fatalf("missing rows: %+v", got)
	}
	if !risky.IsResponsableInscripto {
		t.Fatal("risky responsable flag")
	}
	if !risky.HasRiskyActividades {
		t.Fatalf("CLAE 6499 must flag risky: %+v", risky)
	}
	if !risky.IsCredentialExposureRisk {
		t.Fatalf("risky + world-readable must flag exposure: %+v", risky)
	}
	if mono.SituacionIVA != SituacionMonotributista {
		t.Fatalf("mono situacion=%q", mono.SituacionIVA)
	}
	if mono.IsCredentialExposureRisk {
		t.Fatalf("mono 0o600 must NOT flag: %+v", mono)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
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
		{FilePath: "z", TargetCuitPrefix: "30"},
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
