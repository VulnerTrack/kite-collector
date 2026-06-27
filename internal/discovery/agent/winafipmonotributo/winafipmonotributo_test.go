package winafipmonotributo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRecategorizacion), "recategorizacion"},
		{string(KindPagoMensual), "pago-mensual"},
		{string(KindExclusionNotif), "exclusion-notif"},
		{string(KindCategoriaVigente), "categoria-vigente"},
		{string(KindF184Adhesion), "f184-adhesion"},
		{string(KindIngresoAnual), "ingreso-anual"},
		{string(KindCredencialCard), "credencial-card"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(CategoriaA), "a"},
		{string(CategoriaJ), "j"},
		{string(CategoriaK), "k"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"monotributo_20111111119.xml",
		"recategorizacion_202506_27222222227.xml",
		"exclusion_monotributo_001.xml",
		"categoria_monotrib_27222222227.xml",
		"F184_20111111119_202506.xml",
		"credencial_monotrib_001.pdf",
		"pago_monotrib_202506.txt",
		"ingreso_anual_monotrib_202506.xml",
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
		"recategorizacion_202506.xml":     KindRecategorizacion,
		"exclusion_monotributo_001.xml":   KindExclusionNotif,
		"F184_20111111119_202506.xml":     KindF184Adhesion,
		"credencial_monotrib_001.pdf":     KindCredencialCard,
		"pago_monotrib_202506.txt":        KindPagoMensual,
		"ingreso_anual_monotrib_2024.xml": KindIngresoAnual,
		"categoria_monotrib_001.xml":      KindCategoriaVigente,
		"monotributo_other.xml":           KindOther,
		"":                                KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"monotributo_20111111119.xml", "20", "1119"},
		{"natural 27-22222222-7", "27", "2227"},
		{"juridical 30-71234567-8 must be empty", "", ""},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCategoriaFromText(t *testing.T) {
	cases := map[string]Categoria{
		"A":           CategoriaA,
		"Categoria K": CategoriaK,
		"cat j":       CategoriaJ,
		"cat. b":      CategoriaB,
		"":            CategoriaEmpty,
		"z":           CategoriaEmpty,
	}
	for in, want := range cases {
		if got := CategoriaFromText(in); got != want {
			t.Fatalf("CategoriaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsHighCategoria(t *testing.T) {
	yes := []Categoria{CategoriaJ, CategoriaK}
	no := []Categoria{CategoriaA, CategoriaI, CategoriaEmpty}
	for _, v := range yes {
		if !IsHighCategoria(v) {
			t.Fatalf("expected high: %q", v)
		}
	}
	for _, v := range no {
		if IsHighCategoria(v) {
			t.Fatalf("expected NOT high: %q", v)
		}
	}
}

func TestCiiuSectorLetterFromCode(t *testing.T) {
	cases := map[string]string{
		"011000": "a", // agricultura
		"100000": "c", // manufactura
		"450000": "g", // comercio
		"620000": "j", // info / tech
		"680000": "l", // real estate
		"940000": "s", // otros servicios
		"":       "",
		"99":     "s",
		"X":      "",
	}
	for in, want := range cases {
		if got := CiiuSectorLetterFromCode(in); got != want {
			t.Fatalf("CiiuSectorLetterFromCode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("recategorizacion_202506_27222222227.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateHighCategory(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:             KindCategoriaVigente,
		MonotributistaCuitPrefix: "27",
		Categoria:                CategoriaK,
		IngresoAnualARSCents:     80_000_000_000,
		FileMode:                 0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasHighCategory {
		t.Fatal("K must flag high-category")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("CUIT + categoria + readable = exposure")
	}
}

func TestAnnotateExclusion(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindExclusionNotif,
		FileMode:     0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasExclusion {
		t.Fatal("exclusion-notif kind must flag exclusion")
	}
}

func TestAnnotateRecentRecategorization(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:         KindRecategorizacion,
		RecategorizacionDate: "2026-05-15",
		FileMode:             0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentRecategorization {
		t.Fatalf("within 90d must flag: %+v", r)
	}
}

func TestAnnotateOldRecategorization(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:         KindRecategorizacion,
		RecategorizacionDate: "2024-01-01",
		FileMode:             0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentRecategorization {
		t.Fatal("> 90d must NOT flag recent")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:             KindCategoriaVigente,
		MonotributistaCuitPrefix: "27",
		Categoria:                CategoriaK,
		FileMode:                 0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseMonotributo ---------------------------------------------

func TestParseMonotributoXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<monotributo>
  <cuit_monotributista>27222222227</cuit_monotributista>
  <categoria>K</categoria>
  <ciiu>620100</ciiu>
  <ingreso_anual>80000000.00</ingreso_anual>
  <fecha_recategorizacion>2026-05-15</fecha_recategorizacion>
  <periodo>202506</periodo>
</monotributo>`)
	f, ok := ParseMonotributo(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.MonotributistaCuitRaw != "27222222227" {
		t.Fatalf("cuit=%q", f.MonotributistaCuitRaw)
	}
	if f.CategoriaText != "K" {
		t.Fatalf("cat=%q", f.CategoriaText)
	}
	if f.CiiuCode != "620100" {
		t.Fatalf("ciiu=%q", f.CiiuCode)
	}
	if IngresoToARSCents(f.IngresoAnualText) != 8_000_000_000 {
		t.Fatalf("ingreso=%d", IngresoToARSCents(f.IngresoAnualText))
	}
	if f.RecategorizacionDate != "2026-05-15" {
		t.Fatalf("recat=%q", f.RecategorizacionDate)
	}
}

func TestParseMonotributoExclusionNarrative(t *testing.T) {
	body := []byte(`<exclusion>
<cuit_monotributista>27222222227</cuit_monotributista>
<descripcion>Exclusión del régimen por superar tope de ingresos</descripcion>
</exclusion>`)
	f, ok := ParseMonotributo(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasExclusion {
		t.Fatal("exclusion narrative must flag")
	}
}

func TestParseMonotributoEmpty(t *testing.T) {
	if _, ok := ParseMonotributo([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "Monotributo")
	must(t, os.MkdirAll(dir, 0o755))

	// High-category monotributista, world-readable.
	highPath := filepath.Join(dir, "categoria_monotrib_27222222227.xml")
	must(t, os.WriteFile(highPath, []byte(`<?xml version="1.0"?>
<monotributo>
<cuit_monotributista>27222222227</cuit_monotributista>
<categoria>K</categoria>
<ciiu>620100</ciiu>
<ingreso_anual>80000000.00</ingreso_anual>
<periodo>202506</periodo>
</monotributo>`), 0o644))

	// Recategorización recent, locked down.
	recatPath := filepath.Join(dir, "recategorizacion_202506_20111111119.xml")
	must(t, os.WriteFile(recatPath, []byte(`<recat>
<cuit_monotributista>20111111119</cuit_monotributista>
<categoria>D</categoria>
<fecha_recategorizacion>2026-05-15</fecha_recategorizacion>
</recat>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "Monotributo")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "monotributo_skip.xml"),
		[]byte(`<m/>`), 0o644))

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
		t.Fatalf("want 2 (high+recat), got %d: %+v", len(got), got)
	}

	var high, recat Row
	for _, r := range got {
		switch r.FilePath {
		case highPath:
			high = r
		case recatPath:
			recat = r
		}
	}
	if high.ArtifactKind != KindCategoriaVigente {
		t.Fatalf("high kind=%q", high.ArtifactKind)
	}
	if high.MonotributistaCuitPrefix != "27" || high.MonotributistaCuitSuffix4 != "2227" {
		t.Fatalf("high cuit: %+v", high)
	}
	if high.Categoria != CategoriaK {
		t.Fatalf("high categoria=%q", high.Categoria)
	}
	if !high.HasHighCategory {
		t.Fatalf("K must flag high: %+v", high)
	}
	if high.CiiuSectorLetter != "j" {
		t.Fatalf("ciiu 62 → j (info/tech), got %q", high.CiiuSectorLetter)
	}
	if !high.IsCredentialExposureRisk {
		t.Fatalf("readable + CUIT + cat = exposure: %+v", high)
	}

	if recat.ArtifactKind != KindRecategorizacion {
		t.Fatalf("recat kind=%q", recat.ArtifactKind)
	}
	if !recat.HasRecentRecategorization {
		t.Fatalf("2026-05-15 recat within 90d of 2026-06-16: %+v", recat)
	}
	if recat.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", recat)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mono")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "monotributo_27222222227.xml"),
		[]byte(`<m><cuit_monotributista>27222222227</cuit_monotributista></m>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MONOTRIBUTO_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindOther {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-mono"},
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
		{FilePath: "z", ArtifactKind: KindCategoriaVigente},
		{FilePath: "a", ArtifactKind: KindRecategorizacion},
		{FilePath: "a", ArtifactKind: KindCategoriaVigente},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCategoriaVigente {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
