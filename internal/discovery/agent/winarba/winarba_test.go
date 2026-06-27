package winarba

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(AgencyARBA), "arba"},
		{string(AgencyAGIP), "agip"},
		{string(AgencyAPI), "api"},
		{string(AgencyDGRCordoba), "dgr-cordoba"},
		{string(AgencyDGRMendoza), "dgr-mendoza"},
		{string(AgencyDGRMisiones), "dgr-misiones"},
		{string(AgencyAFIP), "afip"},
		{string(AgencyOther), "other"},
		{string(AgencyUnknown), "unknown"},
		{string(KindCITIVentas), "citi-ventas"},
		{string(KindCITICompras), "citi-compras"},
		{string(KindSICORERetenciones), "sicore-retenciones"},
		{string(KindSICOREPercepciones), "sicore-percepciones"},
		{string(KindPadronIIBB), "padron-iibb"},
		{string(KindAlicuotas), "alicuotas"},
		{string(KindCM05), "cm05"},
		{string(KindIIBBDeclaracion), "iibb-declaracion"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestFileKindFromName(t *testing.T) {
	cases := map[string]FileKind{
		"CITI_VENTAS_202506.txt":           KindCITIVentas,
		"citi-compras-2025-06.txt":         KindCITICompras,
		"SICORE_Retenciones_202506.txt":    KindSICORERetenciones,
		"sicore-percepciones-202506.csv":   KindSICOREPercepciones,
		"PADRON_IIBB_alicuotas_202506.txt": KindPadronIIBB,
		"alicuotas-2025-06.csv":            KindAlicuotas,
		"CM05_2025_06.txt":                 KindCM05,
		"iibb_ddjj_202506.txt":             KindIIBBDeclaracion,
		"iibb-export.txt":                  KindIIBBDeclaracion,
		"random.txt":                       KindUnknown,
		"":                                 KindUnknown,
		"citi_misc.txt":                    KindOther, // citi but no direction
		"sicore_misc.txt":                  KindOther,
	}
	for in, want := range cases {
		if got := FileKindFromName(in); got != want {
			t.Fatalf("FileKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAgencyFromPath(t *testing.T) {
	roots := DefaultAgencyRoots()
	cases := map[string]Agency{
		`C:\ARBA\export\citi.txt`:   AgencyARBA,
		`C:\AGIP\padron.txt`:        AgencyAGIP,
		`C:\AFIP\CITI\export.txt`:   AgencyAFIP,
		`/opt/arba/citi-ventas.txt`: AgencyARBA,
		`/home/u/sicore/export.txt`: AgencyAFIP, // sicore token
		`/srv/random/foo.txt`:       AgencyUnknown,
	}
	for in, want := range cases {
		if got := AgencyFromPath(roots, in); got != want {
			t.Fatalf("AgencyFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsSensitiveKind(t *testing.T) {
	yes := []FileKind{
		KindSICORERetenciones, KindSICOREPercepciones,
		KindPadronIIBB, KindCITIVentas, KindCITICompras,
		KindIIBBDeclaracion,
	}
	no := []FileKind{
		KindAlicuotas, KindCM05, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsSensitiveKind(k) {
			t.Fatalf("expected sensitive: %q", k)
		}
	}
	for _, k := range no {
		if IsSensitiveKind(k) {
			t.Fatalf("expected NOT sensitive: %q", k)
		}
	}
}

func TestCuitFingerprintFromName(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"sicore_30-71234567-8_202506.txt", "30", "5678"},
		{"30712345678_padron.txt", "30", "5678"},
		{"no-cuit.txt", "", ""},
		{"11-12345678-9.txt", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintFromName(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprintFromName(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPeriodFromName(t *testing.T) {
	cases := map[string]string{
		"citi-202506.txt":    "202506",
		"sicore_2025-06.txt": "202506",
		"sicore_2025_06.csv": "202506",
		"no-period.txt":      "",
		"sicore_2025-13.txt": "", // invalid month
	}
	for in, want := range cases {
		if got := PeriodFromName(in); got != want {
			t.Fatalf("PeriodFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCountLines(t *testing.T) {
	cases := map[string]int{
		"":          0,
		"a":         1,
		"a\n":       1,
		"a\nb":      2,
		"a\nb\n":    2,
		"a\nb\nc\n": 3,
	}
	for in, want := range cases {
		if got := CountLines([]byte(in)); got != want {
			t.Fatalf("CountLines(%q)=%d want %d", in, got, want)
		}
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotateSensitiveExposure(t *testing.T) {
	r := Row{FileKind: KindSICORERetenciones, FileMode: 0o644, FileSize: 5 << 20}
	AnnotateSecurity(&r)
	if !r.IsHighValueFile {
		t.Fatal("5 MiB must flag high-value")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("sicore + readable must flag exposure")
	}
}

func TestAnnotateAlicuotasNoExposure(t *testing.T) {
	r := Row{FileKind: KindAlicuotas, FileMode: 0o644, FileSize: 100}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("alicuotas (public rate table) must NOT flag")
	}
	if r.IsHighValueFile {
		t.Fatal("100 bytes must NOT flag high-value")
	}
}

func TestAnnotateSensitive0600Clean(t *testing.T) {
	r := Row{FileKind: KindPadronIIBB, FileMode: 0o600, FileSize: 1024}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksARBA(t *testing.T) {
	tmp := t.TempDir()
	arba := filepath.Join(tmp, "ARBA", "Export")
	must(t, os.MkdirAll(arba, 0o755))

	// Sensitive: SICORE retenciones, world-readable, multi-line.
	sicorePath := filepath.Join(arba, "SICORE_Retenciones_202506.txt")
	must(t, os.WriteFile(sicorePath,
		[]byte("hdr\n30712345678|100.00\n30000000007|200.00\n"), 0o644))

	// Non-sensitive: alicuotas CSV.
	aliPath := filepath.Join(arba, "alicuotas-2025-06.csv")
	must(t, os.WriteFile(aliPath, []byte("a,b\n1,2\n"), 0o644))

	// Locked-down padrón.
	padronDir := filepath.Join(tmp, "AGIP")
	must(t, os.MkdirAll(padronDir, 0o755))
	padronPath := filepath.Join(padronDir, "PADRON_IIBB_alicuotas_202506.txt")
	must(t, os.WriteFile(padronPath, []byte("p\n"), 0o600))

	// Unrelated file — must be ignored.
	must(t, os.WriteFile(filepath.Join(arba, "random.txt"),
		[]byte("x"), 0o644))

	c := &fileCollector{
		roots: []AgencyRoot{
			{Path: filepath.Join(tmp, "ARBA"), Agency: AgencyARBA},
			{Path: filepath.Join(tmp, "AGIP"), Agency: AgencyAGIP},
		},
		getenv:   func(string) string { return "" },
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (sicore+alicuotas+padron), got %d: %+v", len(got), got)
	}

	var sicore, ali, padron Row
	for _, r := range got {
		switch r.FilePath {
		case sicorePath:
			sicore = r
		case aliPath:
			ali = r
		case padronPath:
			padron = r
		}
	}
	if sicore.Agency != AgencyARBA || sicore.FileKind != KindSICORERetenciones {
		t.Fatalf("sicore: %+v", sicore)
	}
	if !sicore.IsCredentialExposureRisk {
		t.Fatalf("sicore + readable must flag exposure: %+v", sicore)
	}
	if sicore.PeriodYYYYMM != "202506" {
		t.Fatalf("sicore period=%q", sicore.PeriodYYYYMM)
	}
	if sicore.RecordCount != 3 {
		t.Fatalf("sicore lines=%d want 3", sicore.RecordCount)
	}

	if ali.FileKind != KindAlicuotas || ali.IsCredentialExposureRisk {
		t.Fatalf("alicuotas: %+v", ali)
	}

	if padron.Agency != AgencyAGIP || padron.FileKind != KindPadronIIBB {
		t.Fatalf("padron: %+v", padron)
	}
	if padron.IsCredentialExposureRisk {
		t.Fatalf("0o600 padron must NOT flag: %+v", padron)
	}
}

func TestCollectorRespectsArbaHomeEnv(t *testing.T) {
	tmp := t.TempDir()
	envRoot := filepath.Join(tmp, "custom-arba")
	must(t, os.MkdirAll(envRoot, 0o755))
	must(t, os.WriteFile(filepath.Join(envRoot, "CITI_VENTAS_202506.txt"),
		[]byte("a\n"), 0o644))

	c := &fileCollector{
		roots: nil,
		getenv: func(k string) string {
			if k == "ARBA_HOME" {
				return envRoot
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
	if len(got) != 1 || got[0].Agency != AgencyARBA || got[0].FileKind != KindCITIVentas {
		t.Fatalf("env-root: %+v", got)
	}
}

func TestCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []AgencyRoot{{Path: "/nope/ARBA", Agency: AgencyARBA}},
		getenv:   func(string) string { return "" },
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
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
		{FilePath: "z", Agency: AgencyARBA, FileKind: KindCITIVentas},
		{FilePath: "a", Agency: AgencyAGIP, FileKind: KindPadronIIBB},
		{FilePath: "a", Agency: AgencyARBA, FileKind: KindCITIVentas},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].Agency != AgencyAGIP {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
