package winafipciti

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCITIVentas), "citi-ventas"},
		{string(KindCITICompras), "citi-compras"},
		{string(KindCITIAlicuotas), "citi-alicuotas"},
		{string(KindF2002IVA), "f2002-iva"},
		{string(KindF2002Alicuotas), "f2002-alicuotas"},
		{string(KindComprobantesExport), "comprobantes-export"},
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
		"CITI_VENTAS_202506_30712345678.txt",
		"CITI_COMPRAS_202506_30712345678.txt",
		"citi_alicuotas_202506.txt",
		"F2002_202506.xml",
		"F2002_alicuotas_202506.xml",
		"iva_digital_202506.csv",
		"comprobantes_export.xml",
		"regimen_compras_ventas.txt",
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
		"CITI_VENTAS_202506.txt":     KindCITIVentas,
		"CITI_COMPRAS_202506.txt":    KindCITICompras,
		"citi_alicuotas_202506.txt":  KindCITIAlicuotas,
		"F2002_alicuotas_202506.xml": KindF2002Alicuotas,
		"F2002_202506.xml":           KindF2002IVA,
		"comprobantes_export.xml":    KindComprobantesExport,
		"citi_otro.txt":              KindOther,
		"":                           KindUnknown,
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
		{"CITI_VENTAS_202506_30712345678.txt", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"natural 27-11111111-4", "27", "1114"},
		{"no cuit", "", ""},
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

func TestIsNaturalPersonPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27"}
	no := []string{"30", "33", "34", "", "11"}
	for _, v := range yes {
		if !IsNaturalPersonPrefix(v) {
			t.Fatalf("expected natural-person: %q", v)
		}
	}
	for _, v := range no {
		if IsNaturalPersonPrefix(v) {
			t.Fatalf("expected NOT natural-person: %q", v)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateHighInvoiceCount(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCITIVentas,
		DeclarantCuitPrefix: "30",
		CounterpartyCount:   2000,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighInvoiceCount {
		t.Fatal("2000 counterparties must flag high-count")
	}
}

func TestAnnotateLargeTotal(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCITIVentas,
		DeclarantCuitPrefix: "30",
		TotalNetoARSCents:   100_000_000_000, // 1B ARS
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeTotal {
		t.Fatal("1B ARS must flag large")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("declarant + large + readable = exposure")
	}
}

func TestAnnotateNaturalPersonExposure(t *testing.T) {
	r := Row{
		ArtifactKind:                   KindCITIVentas,
		DeclarantCuitPrefix:            "30",
		DeclarantCuitSuffix4:           "5678",
		CounterpartyCount:              50,
		NaturalPersonCounterpartyCount: 25,
		FileMode:                       0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasNaturalPersonCounterparty {
		t.Fatal("25 natural-person must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("declarant + natural-person + readable = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:                   KindCITIVentas,
		DeclarantCuitPrefix:            "30",
		NaturalPersonCounterpartyCount: 25,
		FileMode:                       0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoDeclarantNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:                   KindCITIVentas,
		NaturalPersonCounterpartyCount: 25,
		FileMode:                       0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no declarant must NOT flag exposure")
	}
}

// -- ParseCITI ----------------------------------------------------

func TestParseCITIVentasTXT(t *testing.T) {
	body := []byte(`cuit_declarante,30712345678
20111111119,Juan Perez,FAC-A,001-00000001,100000.00
27222222227,Maria Lopez,FAC-A,001-00000002,200000.00
30333333334,Acme SA,FAC-A,001-00000003,500000.00
`)
	sum, ok := ParseCITI(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.DeclarantCuitRaw != "30712345678" {
		t.Fatalf("declarant=%q", sum.DeclarantCuitRaw)
	}
	if sum.CounterpartyCount != 3 {
		t.Fatalf("count=%d", sum.CounterpartyCount)
	}
	if sum.NaturalPersonCounterpartyCount != 2 {
		t.Fatalf("natural=%d", sum.NaturalPersonCounterpartyCount)
	}
	if sum.TotalNetoCents != 80_000_000 {
		t.Fatalf("total=%d", sum.TotalNetoCents)
	}
}

func TestParseCITIF2002XML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<f2002>
  <cuit_declarante>30712345678</cuit_declarante>
  <periodo>202506</periodo>
  <comprobante>
    <cuit_cliente>20111111119</cuit_cliente>
    <importe_neto>100000.00</importe_neto>
    <iva>21000.00</iva>
  </comprobante>
  <comprobante>
    <cuit_cliente>30333333334</cuit_cliente>
    <importe_neto>500000.00</importe_neto>
    <iva>105000.00</iva>
  </comprobante>
</f2002>`)
	sum, ok := ParseCITI(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.CounterpartyCount != 2 {
		t.Fatalf("count=%d", sum.CounterpartyCount)
	}
	if sum.NaturalPersonCounterpartyCount != 1 {
		t.Fatalf("natural=%d", sum.NaturalPersonCounterpartyCount)
	}
	if sum.TotalNetoCents != 60_000_000 {
		t.Fatalf("neto=%d", sum.TotalNetoCents)
	}
	if sum.TotalIVACents != 12_600_000 {
		t.Fatalf("iva=%d", sum.TotalIVACents)
	}
	if sum.MaxInvoiceCents != 50_000_000 {
		t.Fatalf("max=%d", sum.MaxInvoiceCents)
	}
}

func TestParseCITIEmpty(t *testing.T) {
	if _, ok := ParseCITI([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "CITI")
	must(t, os.MkdirAll(dir, 0o755))

	// CITI Ventas with natural-person counterparties, readable.
	ventasPath := filepath.Join(dir, "CITI_VENTAS_202506_30712345678.txt")
	must(t, os.WriteFile(ventasPath, []byte(`cuit_declarante,30712345678
20111111119,X,FAC,001-1,100000.00
27222222227,Y,FAC,001-2,200000.00
`), 0o644))

	// F2002 IVA XML, locked down.
	f2002Path := filepath.Join(dir, "F2002_202506.xml")
	must(t, os.WriteFile(f2002Path, []byte(`<?xml version="1.0"?>
<f2002>
<cuit_declarante>30712345678</cuit_declarante>
<periodo>202506</periodo>
<comprobante><cuit_cliente>30333333334</cuit_cliente><importe_neto>50000.00</importe_neto></comprobante>
</f2002>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte("noise"), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "CITI")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "CITI_VENTAS_skip.txt"),
		[]byte("skip"), 0o644))

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
		t.Fatalf("want 2 (ventas+f2002), got %d: %+v", len(got), got)
	}

	var ventas, f2002 Row
	for _, r := range got {
		switch r.FilePath {
		case ventasPath:
			ventas = r
		case f2002Path:
			f2002 = r
		}
	}
	if ventas.ArtifactKind != KindCITIVentas {
		t.Fatalf("ventas kind=%q", ventas.ArtifactKind)
	}
	if ventas.DeclarantCuitPrefix != "30" || ventas.DeclarantCuitSuffix4 != "5678" {
		t.Fatalf("ventas declarant: %+v", ventas)
	}
	if ventas.NaturalPersonCounterpartyCount != 2 {
		t.Fatalf("ventas natural=%d", ventas.NaturalPersonCounterpartyCount)
	}
	if !ventas.HasNaturalPersonCounterparty {
		t.Fatal("must flag natural person")
	}
	if !ventas.IsCredentialExposureRisk {
		t.Fatalf("declarant + natural + readable = exposure: %+v", ventas)
	}

	if f2002.ArtifactKind != KindF2002IVA {
		t.Fatalf("f2002 kind=%q", f2002.ArtifactKind)
	}
	if f2002.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", f2002)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-citi")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "CITI_VENTAS_202506.txt"),
		[]byte(`cuit_declarante,30712345678`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CITI_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCITIVentas {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-citi"},
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
		{FilePath: "z", ArtifactKind: KindCITIVentas},
		{FilePath: "a", ArtifactKind: KindCITIVentas},
		{FilePath: "a", ArtifactKind: KindCITICompras},
	}
	SortRows(in)
	// FilePath asc, then ArtifactKind asc — "citi-compras" < "citi-ventas".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCITICompras {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
