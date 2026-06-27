package winargmaeclear

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "maeclear-config"},
		{string(KindCredentials), "maeclear-credentials"},
		{string(KindSettlementBook), "maeclear-settlement-book"},
		{string(KindAffirmationLog), "maeclear-affirmation-log"},
		{string(KindRepoBook), "maeclear-repo-book"},
		{string(KindLeliqLog), "maeclear-leliq-log"},
		{string(KindDropCopy), "maeclear-drop-copy"},
		{string(KindSessionLog), "maeclear-session-log"},
		{string(KindInstaller), "maeclear-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountBank), "bank"},
		{string(AccountALYC), "alyc"},
		{string(AccountSociedadGerente), "sociedad-gerente"},
		{string(AccountBCRA), "bcra"},
		{string(AccountAuditor), "auditor"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"maeclear_config.xml",
		"maeclear_credentials.json",
		"settlement_202506.xml",
		"liquidacion_202506.xml",
		"afirmacion_log.txt",
		"affirmation.log",
		"repo_book_202506.csv",
		"caucion_book.csv",
		"leliq_settlement.xml",
		"drop_copy.fix",
		"dropcopy.log",
	}
	no := []string{"", "factura.xml", "random.txt", "report.pdf"}
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
		"maeclear_config.xml":       KindConfig,
		"maeclear_credentials.json": KindCredentials,
		"maeclear_api_key.json":     KindCredentials,
		"settlement_202506.xml":     KindSettlementBook,
		"liquidacion_202506.xml":    KindSettlementBook,
		"afirmacion_log.txt":        KindAffirmationLog,
		"affirmation.log":           KindAffirmationLog,
		"repo_book_202506.csv":      KindRepoBook,
		"caucion_book.csv":          KindRepoBook,
		"leliq_settlement.xml":      KindLeliqLog,
		"drop_copy.fix":             KindDropCopy,
		"dropcopy.log":              KindDropCopy,
		"maeclear_session.log":      KindSessionLog,
		"maeclear_setup.msi":        KindInstaller,
		"":                          KindUnknown,
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
		{"counterparty 27-11111111-4", "27", "1114"},
		{"empresa 30-71234567-8", "30", "5678"},
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

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("settlement_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsSovereignBondTicker(t *testing.T) {
	yes := []string{
		"AL30", "AL30D", "GD30", "GD30C", "AY24",
		"TX26", "TC27", "T2X5", "BOPREAL", "PARP", "DICP",
	}
	no := []string{"", "GGAL", "YPFD", "DLR"}
	for _, v := range yes {
		if !IsSovereignBondTicker(v) {
			t.Fatalf("expected sovereign: %q", v)
		}
	}
	for _, v := range no {
		if IsSovereignBondTicker(v) {
			t.Fatalf("expected NOT sovereign: %q", v)
		}
	}
}

func TestIsLeliqTicker(t *testing.T) {
	yes := []string{
		"LELIQ", "LELIQ-USD", "LELIQUSD", "LEDIV",
		"NOCOM", "NOCOM-USD",
	}
	no := []string{"", "GGAL", "AL30", "DLR"}
	for _, v := range yes {
		if !IsLeliqTicker(v) {
			t.Fatalf("expected leliq: %q", v)
		}
	}
	for _, v := range no {
		if IsLeliqTicker(v) {
			t.Fatalf("expected NOT leliq: %q", v)
		}
	}
}

func TestDistinctCounterpartiesInBody(t *testing.T) {
	body := []byte(`27-11111111-4
30-71234567-8
27-11111111-4
20-99999999-1`)
	if got := DistinctCounterpartiesInBody(body); got != 3 {
		t.Fatalf("distinct=%d want 3", got)
	}
}

func TestParticipantIDFromText(t *testing.T) {
	cases := map[string]string{
		`participant_id: 42`:   "42",
		`matricula = 123`:      "123",
		`<mae_id>987</mae_id>`: "987",
		`no participant here`:  "",
	}
	for in, want := range cases {
		if got := ParticipantIDFromText(in); got != want {
			t.Fatalf("ParticipantIDFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindSettlementBook,
		KindAffirmationLog, KindRepoBook, KindLeliqLog,
		KindDropCopy, KindSessionLog,
	}
	no := []ArtifactKind{
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range no {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSettlementBook,
		HasPasswordInConfig: false,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:       KindSettlementBook,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateSettleFails(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSettlementBook,
		SettlementFailCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasSettlementFailure {
		t.Fatal("fail count must flag")
	}
}

func TestAnnotateLongRepo(t *testing.T) {
	r := Row{
		ArtifactKind:     KindRepoBook,
		RepoCount:        5,
		RepoMaxTenorDays: 45,
	}
	AnnotateSecurity(&r)
	if !r.HasRepoActivity {
		t.Fatal("repo activity must flag")
	}
	if !r.HasLongTenorRepo {
		t.Fatal("45-day repo must flag long tenor")
	}
}

func TestAnnotateBCRALeliq(t *testing.T) {
	r := Row{
		ArtifactKind:         KindLeliqLog,
		LeliqSettlementCount: 10,
	}
	AnnotateSecurity(&r)
	if !r.HasBCRALeliqSettlement {
		t.Fatal("leliq count must flag")
	}
}

func TestAnnotateHighVolume(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSettlementBook,
		TotalVolumeARSCents: 200_000_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighSettlementVolume {
		t.Fatal("2 G ARS must flag high volume")
	}
}

func TestParseMAEclearCredentials(t *testing.T) {
	body := []byte(`<MAEclear>
<participant_id>210</participant_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</MAEclear>`)
	f := ParseMAEclearCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.ParticipantID != "210" {
		t.Fatalf("participant=%q", f.ParticipantID)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseMAEclearSettlementBook(t *testing.T) {
	body := []byte(`2026-06-15 settlement_id=1 symbol=AL30 notional=10000000.00 cliente_cuit=27-11111111-4
2026-06-15 settlement_id=2 symbol=GD30 notional=5000000.00
2026-06-15 settlement_id=3 symbol=AL30D notional=2000000.00 settlement_fail=true
`)
	f := ParseMAEclearSettlementBook(body)
	if f.SettlementCount < 3 {
		t.Fatalf("settle=%d", f.SettlementCount)
	}
	if f.SettlementFailCount < 1 {
		t.Fatalf("fails=%d", f.SettlementFailCount)
	}
	if f.SovereignOTCCount < 3 {
		t.Fatalf("sovereign=%d", f.SovereignOTCCount)
	}
	if f.TotalVolumeCents < 1_700_000_000 {
		t.Fatalf("volume=%d", f.TotalVolumeCents)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseMAEclearRepoBook(t *testing.T) {
	body := []byte(`repo_id,counterparty,tenor_days,notional
1,30-71234567-8,7,1000000.00
2,30-99999999-1,45,500000.00
3,30-71234567-8,30,250000.00
`)
	f := ParseMAEclearRepoBook(body)
	if f.RepoCount < 3 {
		t.Fatalf("repos=%d", f.RepoCount)
	}
	if f.RepoMaxTenorDays != 45 {
		t.Fatalf("max tenor=%d want 45", f.RepoMaxTenorDays)
	}
	if f.DistinctCounterparties < 2 {
		t.Fatalf("distinct=%d", f.DistinctCounterparties)
	}
}

func TestParseMAEclearLeliqLog(t *testing.T) {
	body := []byte(`2026-06-15 leliq_id=1 symbol=LELIQ notional=50000000.00
2026-06-15 leliq_id=2 symbol=LELIQ-USD notional=30000000.00
`)
	f := ParseMAEclearLeliqLog(body)
	if f.LeliqSettlementCount < 2 {
		t.Fatalf("leliq=%d", f.LeliqSettlementCount)
	}
	if f.TotalVolumeCents < 8_000_000_000 {
		t.Fatalf("volume=%d", f.TotalVolumeCents)
	}
}

func TestParseMAEclearDropCopy(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=8|49=MAECLEAR|56=ADCAP|10010=DROP|55=AL30
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=MAECLEAR|56=ADCAP|10010=DROP|55=GD30 settle_fail=true
`)
	f := ParseMAEclearDropCopy(body)
	if !f.HasFIXDropCopy {
		t.Fatal("drop copy must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatal("sender")
	}
	if f.FIXTargetCompID == "" {
		t.Fatal("target")
	}
	if f.SettlementFailCount < 1 {
		t.Fatalf("fails=%d", f.SettlementFailCount)
	}
	if f.SovereignOTCCount < 2 {
		t.Fatalf("sovereign=%d", f.SovereignOTCCount)
	}
}

func TestParseMAEclearAffirmationLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 affirmation symbol=AL30 cp=30-71234567-8
2026-06-15 09:30:02 afirmacion symbol=GD30 cp=30-99999999-1
2026-06-15 09:30:03 bilateral_confirm symbol=AL30D cp=20-12345678-9
`)
	f := ParseMAEclearAffirmationLog(body)
	if f.AffirmationCount < 3 {
		t.Fatalf("affirm=%d", f.AffirmationCount)
	}
	if f.DistinctCounterparties < 3 {
		t.Fatalf("distinct=%d", f.DistinctCounterparties)
	}
}

func TestParseMAEclearEmpty(t *testing.T) {
	f := ParseMAEclearCredentials(nil)
	if f.HasPassword || f.ParticipantID != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "MAEclear")
	must(t, os.MkdirAll(filepath.Join(dir, "books"), 0o755))

	cfgPath := filepath.Join(dir, "maeclear_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<MAEclear>
<participant_id>210</participant_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</MAEclear>`), 0o644))

	settlePath := filepath.Join(dir, "books", "settlement_202506.xml")
	must(t, os.WriteFile(settlePath, []byte(`2026-06-15 settlement_id=1 symbol=AL30 notional=150000000000.00 cliente_cuit=27-11111111-4
2026-06-15 settlement_id=2 symbol=GD30 notional=2000000.00 settlement_fail=true
`), 0o644))

	repoPath := filepath.Join(dir, "books", "repo_book_202506.csv")
	must(t, os.WriteFile(repoPath, []byte(`repo_id,counterparty,tenor_days,notional
1,30-71234567-8,45,1000000.00
`), 0o644))

	leliqPath := filepath.Join(dir, "books", "leliq_settlement_202506.xml")
	must(t, os.WriteFile(leliqPath, []byte(`2026-06-15 leliq_id=1 symbol=LELIQ-USD notional=100000000.00
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "MAEclear")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "maeclear_config.xml"),
		[]byte(`<x/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 (cfg+settle+repo+leliq), got %d: %+v", len(got), got)
	}

	var cfg, settle, repo, leliq Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case settlePath:
			settle = r
		case repoPath:
			repo = r
		case leliqPath:
			leliq = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.ParticipantID != "210" {
		t.Fatalf("cfg participant=%q", cfg.ParticipantID)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cuit = exposure: %+v", cfg)
	}

	if settle.ArtifactKind != KindSettlementBook {
		t.Fatalf("settle kind=%q", settle.ArtifactKind)
	}
	if !settle.HasSettlementFailure {
		t.Fatalf("settle must flag fail: %+v", settle)
	}
	if !settle.HasSovereignOTCActivity {
		t.Fatalf("settle must flag sovereign: %+v", settle)
	}
	if !settle.HasHighSettlementVolume {
		t.Fatalf("150 G must flag high volume: %d", settle.TotalVolumeARSCents)
	}

	if repo.ArtifactKind != KindRepoBook {
		t.Fatalf("repo kind=%q", repo.ArtifactKind)
	}
	if !repo.HasRepoActivity {
		t.Fatalf("repo must flag activity: %+v", repo)
	}
	if !repo.HasLongTenorRepo {
		t.Fatalf("45-day must flag long tenor: %d", repo.RepoMaxTenorDays)
	}

	if leliq.ArtifactKind != KindLeliqLog {
		t.Fatalf("leliq kind=%q", leliq.ArtifactKind)
	}
	if !leliq.HasBCRALeliqSettlement {
		t.Fatalf("leliq must flag BCRA settle: %+v", leliq)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-maeclear")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "maeclear_config.xml"),
		[]byte(`<MAEclear><participant_id>42</participant_id></MAEclear>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MAECLEAR_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-maeclear"},
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
		{FilePath: "z", ArtifactKind: KindConfig},
		{FilePath: "a", ArtifactKind: KindSettlementBook},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("abc"))
	b := HashContents([]byte("abc"))
	if a != b {
		t.Fatal("hash drift")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(MAEClearFields{LeliqSettlementCount: 5}) != AccountBank {
		t.Fatal("leliq -> bank")
	}
	if classifyAccount(MAEClearFields{HasFIXDropCopy: true}) != AccountBank {
		t.Fatal("drop-copy -> bank")
	}
	if classifyAccount(MAEClearFields{RepoCount: 1}) != AccountALYC {
		t.Fatal("repo -> alyc")
	}
	if classifyAccount(MAEClearFields{SovereignOTCCount: 1}) != AccountSociedadGerente {
		t.Fatal("sovereign -> sociedad-gerente")
	}
	if classifyAccount(MAEClearFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
