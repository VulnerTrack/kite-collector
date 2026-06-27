package winargfix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRofexFIX44), "rofex-fix44"},
		{string(KindBYMAFix50), "byma-fix50"},
		{string(KindMAEFix44), "mae-fix44"},
		{string(KindPrimaryREST), "primary-rest"},
		{string(KindQuickFIXBridge), "quickfix-bridge"},
		{string(KindConfig), "config"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(VenueRofex), "rofex"},
		{string(VenueBYMA), "byma"},
		{string(VenueMAE), "mae"},
		{string(VenueMTBA), "mtba"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"FIX.4.4-BROKER338-ROFEX.event.log",
		"FIX.4.4-BROKER338-ROFEX.messages.log",
		"FIX.5.0-XYZ-BYMA_ARIES.event.log",
		"quickfix.cfg",
		"rofex_fix_session.log",
		"primary_session_20260615.log",
		"mae_fix.log",
		"byma_aries.cfg",
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

func TestSessionKindFromName(t *testing.T) {
	cases := map[string]SessionKind{
		"FIX.4.4-BR338-ROFEX.event.log":    KindRofexFIX44,
		"FIX.5.0-XYZ-BYMA_ARIES.event.log": KindBYMAFix50,
		"mae_fix.log":                      KindMAEFix44,
		"primary_session_20260615.log":     KindPrimaryREST,
		"quickfix.cfg":                     KindConfig,
		"quickfix-bridge.log":              KindQuickFIXBridge,
		"some-other-fix.log":               KindOther,
		"random.log":                       KindUnknown,
		"":                                 KindUnknown,
	}
	for in, want := range cases {
		if got := SessionKindFromName(in); got != want {
			t.Fatalf("SessionKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVenueFromText(t *testing.T) {
	cases := map[string]Venue{
		"ROFEX_GW": VenueRofex,
		"BYMA_GW":  VenueBYMA,
		"aries":    VenueBYMA,
		"MAE_GW":   VenueMAE,
		"MATBA_GW": VenueMTBA,
		"":         VenueUnknown,
		"OTHER":    VenueOther,
	}
	for in, want := range cases {
		if got := VenueFromText(in); got != want {
			t.Fatalf("VenueFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCompSuffix4(t *testing.T) {
	cases := map[string]string{
		"BROKER338":  "R338",
		"ROFEX":      "OFEX",
		"X":          "X",
		"":           "",
		"FOO-BAR-99": "AR99",
	}
	for in, want := range cases {
		if got := CompSuffix4(in); got != want {
			t.Fatalf("CompSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSenderTargetFromFilename(t *testing.T) {
	cases := []struct {
		name           string
		sender, target string
	}{
		{"FIX.4.4-BROKER338-ROFEX.event.log", "R338", "OFEX"},
		{"FIX.5.0-XYZ-BYMA.messages.log", "XYZ", "BYMA"},
		{"random.log", "", ""},
	}
	for _, c := range cases {
		gotS, gotT := SenderTargetFromFilename(c.name)
		if gotS != c.sender || gotT != c.target {
			t.Fatalf("SenderTargetFromFilename(%q)=(%q,%q) want (%q,%q)",
				c.name, gotS, gotT, c.sender, c.target)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	cases := map[string]string{
		"FIX.4.4-X-ROFEX-20260615.event.log": "202606",
		"primary_session_20260615.log":       "202606",
		"random.log":                         "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"account 30712345678", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no cuit here", "", ""},
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

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateSpoofingPattern(t *testing.T) {
	r := Row{
		SessionKind:  KindRofexFIX44,
		Venue:        VenueRofex,
		OrderCount:   100,
		CancelCount:  80, // 80 %
		MessageCount: 180,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSpoofingPattern {
		t.Fatalf("80%% cancel ratio must flag spoofing: %+v", r)
	}
}

func TestAnnotateNoSpoofing(t *testing.T) {
	r := Row{
		SessionKind:  KindRofexFIX44,
		OrderCount:   100,
		CancelCount:  10,
		MessageCount: 110,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.HasSpoofingPattern {
		t.Fatalf("10%% cancel ratio must NOT flag spoofing: %+v", r)
	}
}

func TestAnnotateExposureRollup(t *testing.T) {
	r := Row{
		SessionKind:        KindBYMAFix50,
		AccountCuitPrefix:  "30",
		AccountCuitSuffix4: "5678",
		MessageCount:       1000,
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAccountCuit {
		t.Fatal("CUIT prefix set must flag has_account_cuit")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + account CUIT + msgs = exposure: %+v", r)
	}
}

func TestAnnotatePasswordExposure(t *testing.T) {
	r := Row{
		SessionKind:        KindQuickFIXBridge,
		AccountCuitPrefix:  "30",
		AccountCuitSuffix4: "5678",
		HasPasswordTag:     true,
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatalf("password + account CUIT + readable = exposure: %+v", r)
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		SessionKind:        KindRofexFIX44,
		AccountCuitPrefix:  "30",
		AccountCuitSuffix4: "5678",
		MessageCount:       1000,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag exposure: %+v", r)
	}
}

// -- ParseFIXLog --------------------------------------------------

func TestParseFIXLogTypical(t *testing.T) {
	// Build SOH-separated FIX log with mix of D/F/8 messages.
	soh := "\x01"
	lines := []string{
		"20260616-13:00:01.000 : 8=FIX.4.4" + soh + "9=100" + soh + "35=A" +
			soh + "49=BROKER338" + soh + "56=ROFEX" + soh + "10=000",
		"20260616-13:01:00.000 : 8=FIX.4.4" + soh + "35=D" + soh + "49=BROKER338" +
			soh + "56=ROFEX" + soh + "1=30712345678" + soh + "10=000",
		"20260616-13:01:30.000 : 8=FIX.4.4" + soh + "35=D" + soh + "10=000",
		"20260616-13:02:00.000 : 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:02:30.000 : 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:02:31.000 : 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:03:00.000 : 8=FIX.4.4" + soh + "35=8" + soh + "10=000",
	}
	body := []byte(strings.Join(lines, "\n"))
	sum, ok := ParseFIXLog(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.SenderCompID != "BROKER338" {
		t.Fatalf("sender=%q", sum.SenderCompID)
	}
	if sum.TargetCompID != "ROFEX" {
		t.Fatalf("target=%q", sum.TargetCompID)
	}
	if sum.AccountRaw != "30712345678" {
		t.Fatalf("account=%q", sum.AccountRaw)
	}
	if sum.OrderCount != 2 {
		t.Fatalf("order count=%d", sum.OrderCount)
	}
	if sum.CancelCount != 3 {
		t.Fatalf("cancel count=%d", sum.CancelCount)
	}
	if sum.ExecCount != 1 {
		t.Fatalf("exec count=%d", sum.ExecCount)
	}
	if sum.MessageCount != 7 {
		t.Fatalf("msg count=%d", sum.MessageCount)
	}
	if sum.FirstSeen != "20260616-13:00:01" {
		t.Fatalf("first=%q", sum.FirstSeen)
	}
	if sum.IsAfterHours {
		t.Fatal("13:00 ART is in venue hours")
	}
}

func TestParseFIXLogPasswordLeak(t *testing.T) {
	soh := "\x01"
	body := []byte("20260616-10:00:00.000 : 8=FIX.4.4" + soh +
		"35=A" + soh + "49=BR" + soh + "56=ROFEX" + soh +
		"554=hunter2" + soh + "10=000")
	sum, ok := ParseFIXLog(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !sum.HasPasswordTag {
		t.Fatalf("tag 554 must flag password leak: %+v", sum)
	}
}

func TestParseFIXLogAfterHours(t *testing.T) {
	soh := "\x01"
	body := []byte("20260616-22:30:00.000 : 8=FIX.4.4" + soh +
		"35=D" + soh + "49=BR" + soh + "56=ROFEX" + soh + "10=000")
	sum, ok := ParseFIXLog(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !sum.IsAfterHours {
		t.Fatal("22:30 ART must flag after-hours")
	}
}

func TestParseFIXLogEmpty(t *testing.T) {
	if _, ok := ParseFIXLog([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "QuickFIX", "log")
	must(t, os.MkdirAll(dir, 0o755))

	// Spoofing-pattern ROFEX session, world-readable.
	soh := "\x01"
	spoofPath := filepath.Join(dir, "FIX.4.4-BROKER338-ROFEX.messages.log")
	spoofBody := strings.Join([]string{
		"20260616-13:00:01.000 8=FIX.4.4" + soh + "35=D" + soh +
			"49=BROKER338" + soh + "56=ROFEX" + soh +
			"1=30712345678" + soh + "10=000",
		"20260616-13:00:02.000 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:00:03.000 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:00:04.000 8=FIX.4.4" + soh + "35=F" + soh + "10=000",
		"20260616-13:00:05.000 8=FIX.4.4" + soh + "35=8" + soh + "10=000",
	}, "\n")
	must(t, os.WriteFile(spoofPath, []byte(spoofBody), 0o644))

	// Config file with password tag, locked down.
	cfgPath := filepath.Join(dir, "quickfix.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`
[SESSION]
SenderCompID=BROKER338
TargetCompID=BYMA_ARIES
Password=hunter2
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.log"),
		[]byte("noise"), 0o644))

	// Public profile skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "QuickFIX", "log")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "FIX.4.4-X-ROFEX.event.log"),
		[]byte("skip"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (spoof+cfg), got %d: %+v", len(got), got)
	}

	var spoof, cfg Row
	for _, r := range got {
		switch r.FilePath {
		case spoofPath:
			spoof = r
		case cfgPath:
			cfg = r
		}
	}
	if spoof.SessionKind != KindRofexFIX44 {
		t.Fatalf("spoof kind=%q", spoof.SessionKind)
	}
	if spoof.Venue != VenueRofex {
		t.Fatalf("spoof venue=%q", spoof.Venue)
	}
	if !spoof.HasSpoofingPattern {
		t.Fatalf("3 cancels / 1 order must flag spoof: %+v", spoof)
	}
	if !spoof.HasAccountCuit {
		t.Fatalf("CUIT account must flag: %+v", spoof)
	}
	if !spoof.IsCredentialExposureRisk {
		t.Fatalf("readable + CUIT + msgs = exposure: %+v", spoof)
	}
	if spoof.AccountCuitPrefix != "30" || spoof.AccountCuitSuffix4 != "5678" {
		t.Fatalf("spoof account: %+v", spoof)
	}
	if spoof.SenderCompSuffix4 != "R338" {
		t.Fatalf("spoof sender suffix=%q", spoof.SenderCompSuffix4)
	}

	if cfg.SessionKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.SessionKind)
	}
	if !cfg.HasPasswordTag {
		t.Fatalf("cfg must flag password leak: %+v", cfg)
	}
	if cfg.IsCredentialExposureRisk {
		t.Fatalf("0o600 cfg must NOT flag exposure: %+v", cfg)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-fix")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "FIX.4.4-X-ROFEX.event.log"),
		[]byte("noise"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FIX_LOG_DIR" {
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
	if len(got) != 1 || got[0].SessionKind != KindRofexFIX44 {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-fix"},
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
		{FilePath: "z", SessionKind: KindRofexFIX44},
		{FilePath: "a", SessionKind: KindBYMAFix50},
		{FilePath: "a", SessionKind: KindMAEFix44},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].SessionKind != KindBYMAFix50 {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
