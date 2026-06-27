package winafipdfe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(NotifIntimacionPago), "intimacion-pago"},
		{string(NotifRequerimientoDoc), "requerimiento-documentacion"},
		{string(NotifProcDeterminacion), "inicio-procedimiento-doficio"},
		{string(NotifSancion), "sancion"},
		{string(NotifMulta), "multa"},
		{string(NotifAjusteImpositivo), "ajuste-impositivo"},
		{string(NotifComunicacionGeneral), "comunicacion-general"},
		{string(NotifCitacion), "citacion"},
		{string(NotifOther), "other"},
		{string(NotifUnknown), "unknown"},
		{string(EstadoPendiente), "pendiente"},
		{string(EstadoLeida), "leida"},
		{string(EstadoContestada), "contestada"},
		{string(EstadoVencida), "vencida"},
		{string(EstadoArchivada), "archivada"},
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
		"DFE_30712345678_001.pdf",
		"e-ventanilla_2024.xml",
		"intimacion_pago_30712345678.pdf",
		"requerimiento_afip_001.pdf",
		"multa_afip_001.pdf",
		"determinacion_oficio_2024.pdf",
		"notif_afip_001.xml",
	}
	no := []string{"", "factura.pdf", "cv.docx"}
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

func TestNotificationKindFromName(t *testing.T) {
	cases := map[string]NotificationKind{
		"intimacion_pago_001.pdf":       NotifIntimacionPago,
		"intimación_001.xml":            NotifIntimacionPago,
		"determinacion_oficio_2024.pdf": NotifProcDeterminacion,
		"requerimiento_afip_001.pdf":    NotifRequerimientoDoc,
		"multa_afip_001.pdf":            NotifMulta,
		"sancion_afip_001.pdf":          NotifSancion,
		"ajuste_impositivo_001.pdf":     NotifAjusteImpositivo,
		"citacion_afip_001.pdf":         NotifCitacion,
		"comunicacion_general_001.pdf":  NotifComunicacionGeneral,
		"DFE_30712345678.pdf":           NotifOther,
		"e-ventanilla_2024.xml":         NotifOther,
		"random.pdf":                    NotifUnknown,
		"":                              NotifUnknown,
	}
	for in, want := range cases {
		if got := NotificationKindFromName(in); got != want {
			t.Fatalf("NotificationKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEstadoFromText(t *testing.T) {
	cases := map[string]Estado{
		"Pendiente":  EstadoPendiente,
		"pending":    EstadoPendiente,
		"Leída":      EstadoLeida,
		"Contestada": EstadoContestada,
		"Vencida":    EstadoVencida,
		"overdue":    EstadoVencida,
		"Archivada":  EstadoArchivada,
		"":           EstadoUnknown,
		"otra":       EstadoUnknown,
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
		{"DFE_30712345678_001.pdf", "30", "5678"},
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

func TestNumeroFromText(t *testing.T) {
	cases := map[string]string{
		"N° 1234567":  "1234567",
		"Nro: 9999":   "9999",
		"#12345":      "12345",
		"Numero 9999": "9999",
		"no numero":   "",
		"":            "",
	}
	for in, want := range cases {
		if got := NumeroFromText(in); got != want {
			t.Fatalf("NumeroFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseFecha(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"2024-06-15", true},
		{"15/06/2024", true},
		{"15-06-2024", true},
		{"2024/06/15", true},
		{"invalid", false},
		{"", false},
	}
	for _, c := range cases {
		got := ParseFecha(c.in)
		if c.ok && got.IsZero() {
			t.Fatalf("ParseFecha(%q) should parse", c.in)
		}
		if !c.ok && !got.IsZero() {
			t.Fatalf("ParseFecha(%q) should fail", c.in)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateIntimacionExposure(t *testing.T) {
	r := Row{
		NotificationKind: NotifIntimacionPago,
		Estado:           EstadoPendiente,
		MontoARSCents:    5_000_000_000, // 50 M ARS
		TargetCuitPrefix: "30",
		FileMode:         0o644,
	}
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	AnnotateSecurityWithClock(&r, now)
	if !r.IsIntimacionPago {
		t.Fatal("intimacion kind must flag")
	}
	if !r.IsHighValue {
		t.Fatal("50M ARS must flag high-value")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable DFE must flag exposure")
	}
}

func TestAnnotatePendingDeadlineSoon(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		NotificationKind: NotifRequerimientoDoc,
		Estado:           EstadoPendiente,
		FechaVencimiento: "2026-06-30",
		FileMode:         0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPendingResponse {
		t.Fatal("deadline 15d out must flag pending-response")
	}
	if r.IsOverdue {
		t.Fatal("future deadline must NOT flag overdue")
	}
}

func TestAnnotatePendingDeadlinePastIsOverdue(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		NotificationKind: NotifRequerimientoDoc,
		Estado:           EstadoPendiente,
		FechaVencimiento: "2026-05-01",
		FileMode:         0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsOverdue {
		t.Fatal("past deadline + pendiente must flag overdue")
	}
}

func TestAnnotateAuditInitiation(t *testing.T) {
	r := Row{NotificationKind: NotifProcDeterminacion, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsAuditInitiation {
		t.Fatal("determinacion-oficio must flag audit initiation")
	}
}

func TestAnnotateSancionMulta(t *testing.T) {
	for _, k := range []NotificationKind{NotifSancion, NotifMulta} {
		r := Row{NotificationKind: k, FileMode: 0o600}
		AnnotateSecurity(&r)
		if !r.IsSancion {
			t.Fatalf("%q must flag sancion", k)
		}
	}
}

func TestAnnotateVencidaIsOverdue(t *testing.T) {
	r := Row{NotificationKind: NotifIntimacionPago, Estado: EstadoVencida, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsOverdue {
		t.Fatal("estado=vencida must flag overdue")
	}
}

// -- ParseDFE ------------------------------------------------------

func TestParseDFEXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<notificacionDFE>
  <cuit>30-71234567-8</cuit>
  <numero>1234567</numero>
  <tipo>Intimación de Pago</tipo>
  <fecha_notificacion>2024-06-15</fecha_notificacion>
  <fecha_vencimiento>2024-07-15</fecha_vencimiento>
  <estado>Pendiente</estado>
  <monto>5000000.00</monto>
  <impuesto>IVA</impuesto>
</notificacionDFE>`)
	f, ok := ParseDFE(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TargetCuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.TargetCuitRaw)
	}
	if f.NumeroNotificacion != "1234567" {
		t.Fatalf("numero=%q", f.NumeroNotificacion)
	}
	if f.MontoARSCents != 500000000 {
		t.Fatalf("monto cents=%d want 500000000", f.MontoARSCents)
	}
	if f.Impuesto != "IVA" {
		t.Fatalf("impuesto=%q", f.Impuesto)
	}
}

func TestParseDFEJSON(t *testing.T) {
	body := []byte(`{
  "cuit": "30712345678",
  "numero": "1234567",
  "tipo": "Sanción",
  "estado": "Pendiente",
  "monto": "1234567.89",
  "impuesto": "Ganancias"
}`)
	f, ok := ParseDFE(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Impuesto != "Ganancias" {
		t.Fatalf("impuesto=%q", f.Impuesto)
	}
}

func TestParseDFEArsThousands(t *testing.T) {
	body := []byte(`monto = $1.234.567,89`)
	f, ok := ParseDFE(body)
	if !ok || f.MontoARSCents != 123456789 {
		t.Fatalf("ARS thousand format: %+v", f)
	}
}

func TestParseDFEEmpty(t *testing.T) {
	if _, ok := ParseDFE([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "DFE")
	must(t, os.MkdirAll(dir, 0o755))

	// Intimación high-value, world-readable.
	intPath := filepath.Join(dir, "intimacion_pago_30712345678_001.xml")
	must(t, os.WriteFile(intPath, []byte(`<notificacionDFE>
<cuit>30712345678</cuit>
<numero>1234567</numero>
<tipo>Intimación de Pago</tipo>
<fecha_notificacion>2024-06-15</fecha_notificacion>
<fecha_vencimiento>2024-07-15</fecha_vencimiento>
<estado>Pendiente</estado>
<monto>50000000.00</monto>
</notificacionDFE>`), 0o644))

	// Sanción locked-down.
	sancPath := filepath.Join(dir, "sancion_afip_30000000007_001.pdf")
	must(t, os.WriteFile(sancPath, []byte("%PDF"), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.pdf"), []byte("%PDF"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "DFE")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "DFE_skip.pdf"), []byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (int+sanc), got %d: %+v", len(got), got)
	}

	var intRow, sancRow Row
	for _, r := range got {
		switch r.FilePath {
		case intPath:
			intRow = r
		case sancPath:
			sancRow = r
		}
	}
	if !intRow.IsIntimacionPago {
		t.Fatalf("int flags: %+v", intRow)
	}
	if !intRow.IsHighValue {
		t.Fatalf("int must flag high-value: %+v", intRow)
	}
	if !intRow.IsOverdue {
		t.Fatalf("vencimiento past (2024 vs 2026 now) must flag overdue: %+v", intRow)
	}
	if !intRow.IsCredentialExposureRisk {
		t.Fatalf("int + readable = exposure: %+v", intRow)
	}

	if !sancRow.IsSancion {
		t.Fatalf("sanc must flag: %+v", sancRow)
	}
	if sancRow.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", sancRow)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-dfe")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "DFE_30712345678.pdf"),
		[]byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AFIP_DFE_DIR" {
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
	if len(got) != 1 || got[0].TargetCuitPrefix != "30" {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-dfe"},
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
