package winargbeneficiarios

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(FilingAnual), "beneficiario-final-anual"},
		{string(FilingModificacion), "beneficiario-final-modificacion"},
		{string(FilingDDJJBorrador), "ddjj-borrador"},
		{string(FilingF8127), "f8127"},
		{string(FilingRISBF), "ris-bf"},
		{string(FilingOther), "other"},
		{string(FilingUnknown), "unknown"},
		{string(EstadoPresentada), "presentada"},
		{string(EstadoRectificada), "rectificada"},
		{string(EstadoBorrador), "borrador"},
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
		"BeneficiarioFinal_30712345678_2024.xml",
		"beneficiario_final_acme.json",
		"RIS_BF_30000000007.txt",
		"F8127_acme.pdf",
		"RG4697_2024.xml",
		"DDJJ_BF_borrador.xml",
		"UBO_acme.json",
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

func TestFilingKindFromName(t *testing.T) {
	cases := map[string]FilingKind{
		"F8127_30712345678.pdf":             FilingF8127,
		"f.8127.pdf":                        FilingF8127,
		"RIS_BF_30712345678_2024.txt":       FilingRISBF,
		"BeneficiarioFinal_borrador.xml":    FilingDDJJBorrador,
		"modificacion_BF_2024.xml":          FilingModificacion,
		"rectificativa_BF_2024.xml":         FilingModificacion,
		"BeneficiarioFinal_30712345678.xml": FilingAnual,
		"RG4697_2024.xml":                   FilingAnual,
		"UBO_acme.json":                     FilingAnual,
		"ddjj_bf_2024.xml":                  FilingAnual,
		"random_beneficiario_.xml":          FilingOther,
		"":                                  FilingUnknown,
	}
	for in, want := range cases {
		if got := FilingKindFromName(in); got != want {
			t.Fatalf("FilingKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEstadoFromText(t *testing.T) {
	cases := map[string]Estado{
		"Presentada":  EstadoPresentada,
		"SUBMITTED":   EstadoPresentada,
		"transmitida": EstadoPresentada,
		"Rectificada": EstadoRectificada,
		"Borrador":    EstadoBorrador,
		"Draft":       EstadoBorrador,
		"":            EstadoUnknown,
		"otra":        EstadoUnknown,
	}
	for in, want := range cases {
		if got := EstadoFromText(in); got != want {
			t.Fatalf("EstadoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPrefixClassifiers(t *testing.T) {
	if !IsJuridicalPrefix("30") || !IsJuridicalPrefix("33") {
		t.Fatal("30/33 must be juridical")
	}
	if IsJuridicalPrefix("20") {
		t.Fatal("20 must NOT be juridical")
	}
	if !IsNaturalPersonPrefix("20") || !IsNaturalPersonPrefix("27") {
		t.Fatal("20/27 must be natural-person")
	}
	if IsNaturalPersonPrefix("30") {
		t.Fatal("30 must NOT be natural-person")
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"BeneficiarioFinal_30712345678.xml", "30", "5678"},
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

func TestPeriodFromName(t *testing.T) {
	cases := map[string]string{
		"BeneficiarioFinal_30712345678_2024.xml": "2024",
		"BF_2023.xml":                            "2023",
		"BF.xml":                                 "",
	}
	for in, want := range cases {
		if got := PeriodFromName(in); got != want {
			t.Fatalf("PeriodFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighConcentrationExposure(t *testing.T) {
	r := Row{
		FilingKind:          FilingAnual,
		Estado:              EstadoPresentada,
		ObligadoCuitPrefix:  "30",
		ObligadoCuitSuffix4: "5678",
		BeneficiariosCount:  1,
		MaxParticipacionPct: 100,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsHighConcentration {
		t.Fatal("100% must flag high-concentration")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("UBO + readable must flag exposure")
	}
	if r.IsBorrador {
		t.Fatal("presentada must NOT flag borrador")
	}
}

func TestAnnotateBorradorFromEstado(t *testing.T) {
	r := Row{
		FilingKind:         FilingAnual,
		Estado:             EstadoBorrador,
		ObligadoCuitPrefix: "30",
		BeneficiariosCount: 2,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsBorrador {
		t.Fatal("estado=borrador must flag")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateBorradorFromKind(t *testing.T) {
	r := Row{FilingKind: FilingDDJJBorrador, Estado: EstadoUnknown, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsBorrador {
		t.Fatal("FilingDDJJBorrador must flag borrador")
	}
}

func TestAnnotateLowConcentrationClean(t *testing.T) {
	r := Row{
		FilingKind:          FilingAnual,
		Estado:              EstadoPresentada,
		MaxParticipacionPct: 25,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsHighConcentration {
		t.Fatal("25% must NOT flag high-concentration")
	}
}

// -- ParseUBODeclaration -------------------------------------------

func TestParseUBODeclarationXMLHighConcentration(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<beneficiarioFinal>
  <cuitObligado>30-71234567-8</cuitObligado>
  <denominacion>ACME S.A.</denominacion>
  <periodo>2024</periodo>
  <estado>Presentada</estado>
  <beneficiarios>
    <beneficiario>
      <cuil>20-12345678-9</cuil>
      <participacion>100</participacion>
      <tipoControl>directo</tipoControl>
    </beneficiario>
  </beneficiarios>
</beneficiarioFinal>`)
	f, ok := ParseUBODeclaration(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.ObligadoCuitRaw != "30-71234567-8" {
		t.Fatalf("obligado=%q", f.ObligadoCuitRaw)
	}
	if f.BeneficiariosCount != 1 || f.MaxParticipacionPct != 100 {
		t.Fatalf("benes/max: %+v", f)
	}
	if f.PeriodYYYY != "2024" || f.EstadoText != "Presentada" {
		t.Fatalf("period/estado: %+v", f)
	}
	if f.HasIndirectControlChain {
		t.Fatal("directo control must NOT flag indirect chain")
	}
}

func TestParseUBODeclarationXMLIndirectChainViaJuridical(t *testing.T) {
	body := []byte(`<beneficiarioFinal>
<cuitObligado>30712345678</cuitObligado>
<beneficiarios>
<beneficiario><cuil>30000000007</cuil><participacion>60</participacion><tipoControl>directo</tipoControl></beneficiario>
<beneficiario><cuil>20111111112</cuil><participacion>40</participacion><tipoControl>indirecto</tipoControl></beneficiario>
</beneficiarios>
</beneficiarioFinal>`)
	f, ok := ParseUBODeclaration(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasIndirectControlChain {
		t.Fatal("juridical 30-prefix beneficiario must flag indirect chain")
	}
	if f.MaxParticipacionPct != 60 {
		t.Fatalf("max=%d want 60", f.MaxParticipacionPct)
	}
	if f.BeneficiariosCount != 2 {
		t.Fatalf("count=%d want 2", f.BeneficiariosCount)
	}
}

func TestParseUBODeclarationXMLExtranjero(t *testing.T) {
	body := []byte(`<beneficiarioFinal>
<cuitObligado>30712345678</cuitObligado>
<beneficiarios>
<beneficiario>
  <iddocumento>X12345678</iddocumento>
  <tipodocumento>Pasaporte</tipodocumento>
  <participacion>30</participacion>
  <paisresidencia>USA</paisresidencia>
</beneficiario>
</beneficiarios>
</beneficiarioFinal>`)
	f, ok := ParseUBODeclaration(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasExtranjeroUBO {
		t.Fatal("pasaporte + USA must flag extranjero UBO")
	}
}

func TestParseUBODeclarationJSON(t *testing.T) {
	body := []byte(`{
  "cuitObligado": "30712345678",
  "denominacion": "ACME S.A.",
  "periodo": "2024",
  "estado": "Borrador",
  "beneficiarios": [
    {"cuil": "20111111112", "participacion": 75, "tipoControl": "directo"}
  ]
}`)
	f, ok := ParseUBODeclaration(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.MaxParticipacionPct != 75 {
		t.Fatalf("max=%d want 75", f.MaxParticipacionPct)
	}
	if f.EstadoText != "Borrador" {
		t.Fatalf("estado=%q", f.EstadoText)
	}
}

func TestParseUBODeclarationRejectsGarbage(t *testing.T) {
	if _, ok := ParseUBODeclaration([]byte("nope")); ok {
		t.Fatal("garbage must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	alice := filepath.Join(usersBase, "alice", "Documents", "AFIP", "BeneficiarioFinal")
	must(t, os.MkdirAll(alice, 0o755))

	// High-concentration single-owner XML, world-readable.
	highPath := filepath.Join(alice, "BeneficiarioFinal_30712345678_2024.xml")
	must(t, os.WriteFile(highPath, []byte(`<beneficiarioFinal>
<cuitObligado>30712345678</cuitObligado>
<denominacion>ACME S.A.</denominacion>
<periodo>2024</periodo>
<estado>Presentada</estado>
<beneficiarios>
<beneficiario><cuil>20-12345678-9</cuil><participacion>100</participacion><tipoControl>directo</tipoControl></beneficiario>
</beneficiarios>
</beneficiarioFinal>`), 0o644))

	// Borrador JSON locked-down.
	borrPath := filepath.Join(alice, "ubo_30000000007_borrador.json")
	must(t, os.WriteFile(borrPath, []byte(`{
"cuitObligado":"30000000007",
"estado":"Borrador",
"beneficiarios":[{"cuil":"20111111112","participacion":40}]
}`), 0o600))

	// Unrelated XML — ignored.
	must(t, os.WriteFile(filepath.Join(alice, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public profile — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "BeneficiarioFinal")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "BeneficiarioFinal_skip.xml"),
		[]byte(`<beneficiarioFinal/>`), 0o644))

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
		t.Fatalf("want 2 (high+borr), got %d: %+v", len(got), got)
	}

	var high, borr Row
	for _, r := range got {
		switch r.FilePath {
		case highPath:
			high = r
		case borrPath:
			borr = r
		}
	}
	if high.FilePath == "" || borr.FilePath == "" {
		t.Fatalf("missing rows: %+v", got)
	}
	if !high.IsHighConcentration {
		t.Fatalf("high 100%% must flag concentration: %+v", high)
	}
	if high.ObligadoCuitPrefix != "30" || high.ObligadoCuitSuffix4 != "5678" {
		t.Fatalf("high cuit: %+v", high)
	}
	if !high.IsCredentialExposureRisk {
		t.Fatalf("high UBO + readable must flag exposure: %+v", high)
	}
	if !borr.IsBorrador {
		t.Fatalf("borr must flag borrador: %+v", borr)
	}
	if borr.IsCredentialExposureRisk {
		t.Fatalf("borr 0o600 must NOT flag: %+v", borr)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bf")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "BeneficiarioFinal_30712345678.xml"),
		[]byte(`<beneficiarioFinal>
<cuitObligado>30712345678</cuitObligado>
<estado>Presentada</estado>
<beneficiarios><beneficiario><cuil>20111111112</cuil><participacion>100</participacion></beneficiario></beneficiarios>
</beneficiarioFinal>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AFIP_BF_DIR" {
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
	if len(got) != 1 || !got[0].IsHighConcentration {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-bf"},
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
		{FilePath: "z", ObligadoCuitPrefix: "30", ObligadoCuitSuffix4: "1111"},
		{FilePath: "a", ObligadoCuitPrefix: "30", ObligadoCuitSuffix4: "9999"},
		{FilePath: "a", ObligadoCuitPrefix: "20", ObligadoCuitSuffix4: "0001"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ObligadoCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
