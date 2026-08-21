package winargma

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// fixedNow pins the clock to 2026-06-16 UTC for hermetic tests.
func fixedNow() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

// fakeFileInfo is a minimal os.FileInfo used to drive ownerUID and
// consider without touching the real filesystem.
type fakeFileInfo struct {
	mod  time.Time
	sys  any
	name string
	size int64
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.sys }

// -- constructor + identity ---------------------------------------

func TestNewCollectorName(t *testing.T) {
	c := NewCollector()
	if got := c.Name(); got != "winargma" {
		t.Fatalf("Name()=%q want winargma", got)
	}
}

func TestConstantsPinned(t *testing.T) {
	if MaxRows != 16384 {
		t.Fatalf("MaxRows=%d want 16384", MaxRows)
	}
	if MaxFileBytes != 16<<20 {
		t.Fatalf("MaxFileBytes=%d want 16MiB", MaxFileBytes)
	}
	if RecentlyWindow != 90*24*time.Hour {
		t.Fatalf("RecentlyWindow=%v want 90d", RecentlyWindow)
	}
	if MaxWalkDepth != 6 {
		t.Fatalf("MaxWalkDepth=%d want 6", MaxWalkDepth)
	}
	if LargeBidderRosterThreshold != 10 {
		t.Fatalf("LargeBidderRosterThreshold=%d want 10", LargeBidderRosterThreshold)
	}
	if LargeDataroomThreshold != 100 {
		t.Fatalf("LargeDataroomThreshold=%d want 100", LargeDataroomThreshold)
	}
}

func TestDefaultRootsAndBases(t *testing.T) {
	if got := DefaultInstallRoots(); len(got) != 6 {
		t.Fatalf("DefaultInstallRoots len=%d want 6", len(got))
	}
	if got := DefaultUsersBases(); len(got) != 3 {
		t.Fatalf("DefaultUsersBases len=%d want 3", len(got))
	}
}

// -- ownerUID (non-Stat_t branch) ---------------------------------

func TestOwnerUIDNonStat(t *testing.T) {
	if got := ownerUID(fakeFileInfo{name: "x", sys: "not-a-stat"}); got != 0 {
		t.Fatalf("ownerUID(non-stat)=%d want 0", got)
	}
	if got := ownerUID(fakeFileInfo{name: "y", sys: nil}); got != 0 {
		t.Fatalf("ownerUID(nil sys)=%d want 0", got)
	}
}

// -- parsers: exact returned values -------------------------------

func TestParseNDAFields(t *testing.T) {
	f := ParseNDA([]byte("NDA - Project Tango\n" +
		"DRAFT - CONFIDENTIAL\n" +
		"deal_id: DEAL-2026-0002\n" +
		"target_cuit: 30-71234567-8\n"))
	if f.DealID != "DEAL-2026-0002" {
		t.Fatalf("deal=%q", f.DealID)
	}
	if !f.HasPreAnnouncementDraft {
		t.Fatal("DRAFT must flag pre-announcement")
	}
	if f.TargetCuitRaw != "30-71234567-8" {
		t.Fatalf("target cuit raw=%q", f.TargetCuitRaw)
	}
}

func TestParseInformationMemorandumFields(t *testing.T) {
	f := ParseInformationMemorandum([]byte("Information Memorandum\n" +
		"enterprise_value: 50000000000\n"))
	if f.EnterpriseValueARSMillions != 50_000 {
		t.Fatalf("EV=%d want 50000", f.EnterpriseValueARSMillions)
	}
}

func TestParseProcessLetterFields(t *testing.T) {
	f := ParseProcessLetter([]byte("Process Letter - Round 2\n" +
		"RESTRICTED\n" +
		"deal_id: DEAL-2026-0003\n"))
	if f.DealID != "DEAL-2026-0003" {
		t.Fatalf("deal=%q", f.DealID)
	}
	if !f.HasPreAnnouncementDraft {
		t.Fatal("RESTRICTED must flag pre-announcement")
	}
}

func TestParseBidEvaluationFields(t *testing.T) {
	f := ParseBidEvaluation([]byte("Bid Evaluation\nbidder_count: 7\n"))
	if f.BidderCount != 7 {
		t.Fatalf("bidder count=%d want 7", f.BidderCount)
	}
}

func TestParseBidEvaluationRowFallback(t *testing.T) {
	f := ParseBidEvaluation([]byte("Bid Evaluation\n" +
		"BID-001,30-71234567-8,x\n"))
	if f.BidderCount != 1 {
		t.Fatalf("bidder count fallback=%d want 1", f.BidderCount)
	}
}

func TestParseBidderRosterRowFallback(t *testing.T) {
	f := ParseBidderRoster([]byte("Bidder Roster\n" +
		"BIDDER-001,30-71234567-8,Strategic\n" +
		"BIDDER-002,30-99999999-1,Sponsor\n"))
	if f.BidderCount != 2 {
		t.Fatalf("bidder count fallback=%d want 2", f.BidderCount)
	}
}

func TestParseDataroomManifestRowFallback(t *testing.T) {
	f := ParseDataroomManifest([]byte("Dataroom Manifest\n" +
		"DOC-001,Financials,5MB\n" +
		"DOC-002,Legal,3MB\n"))
	if f.DataroomFileCount != 2 {
		t.Fatalf("dataroom fallback=%d want 2", f.DataroomFileCount)
	}
}

func TestParseLBOModelFields(t *testing.T) {
	f := ParseLBOModel([]byte("LBO Model\nenterprise_value: 30000000000\n"))
	if f.EnterpriseValueARSMillions != 30_000 {
		t.Fatalf("EV=%d want 30000", f.EnterpriseValueARSMillions)
	}
}

func TestParseMergerModelFields(t *testing.T) {
	f := ParseMergerModel([]byte("Merger Model\nenterprise_value: 20000000000\n"))
	if f.EnterpriseValueARSMillions != 20_000 {
		t.Fatalf("EV=%d want 20000", f.EnterpriseValueARSMillions)
	}
}

func TestParseSPADraftFields(t *testing.T) {
	f := ParseSPADraft([]byte("SPA Draft\n" +
		"enterprise_value: 15000000000\n" +
		"target_cuit: 30-71234567-8\n"))
	if f.EnterpriseValueARSMillions != 15_000 {
		t.Fatalf("EV=%d want 15000", f.EnterpriseValueARSMillions)
	}
	if f.TargetCuitRaw != "30-71234567-8" {
		t.Fatalf("target cuit raw=%q", f.TargetCuitRaw)
	}
}

func TestParseCommonBackedParsers(t *testing.T) {
	body := []byte("Doc\nCONFIDENTIAL\n" +
		"deal_id: DEAL-2026-0009\n" +
		"advisor_firm: JPMorgan\n")
	got := map[string]MAFields{
		"qofe":       ParseQofEReport(body),
		"disclosure": ParseDisclosureSchedules(body),
		"fairness":   ParseFairnessOpinion(body),
		"synergy":    ParseSynergyAnalysis(body),
		"antitrust":  ParseAntitrustMemo(body),
	}
	for name, f := range got {
		if f.DealID != "DEAL-2026-0009" {
			t.Fatalf("%s deal id=%q", name, f.DealID)
		}
		if f.AdvisorFirm != FirmJPMorganArgentina {
			t.Fatalf("%s firm=%q", name, f.AdvisorFirm)
		}
		if !f.HasPreAnnouncementDraft {
			t.Fatalf("%s must flag CONFIDENTIAL", name)
		}
	}
}

func TestParseCommonEmptyAndMalformed(t *testing.T) {
	if f := ParsePitchDeck(nil); f.DealID != "" || f.HasPassword {
		t.Fatalf("nil body must be zero: %+v", f)
	}
	if f := ParsePitchDeck([]byte("")); f.DealID != "" {
		t.Fatalf("empty body must be zero: %+v", f)
	}
	f := ParseNDA([]byte("!!! not structured @@@ 123 ###"))
	if f.DealID != "" || f.HasPassword || f.HasPreAnnouncementDraft {
		t.Fatalf("malformed body must be zero: %+v", f)
	}
}

// -- classifiers --------------------------------------------------

func TestIsCandidateExtValues(t *testing.T) {
	yes := []string{"a.pdf", "b.xlsx", "c.msi", "d.PDF", "e.CSV", "f.docx", "g.pptx"}
	for _, n := range yes {
		if !IsCandidateExt(n) {
			t.Fatalf("expected candidate ext: %q", n)
		}
	}
	no := []string{"a.zip", "b.rtf", "noext", "c.7z", "", "d.tar"}
	for _, n := range no {
		if IsCandidateExt(n) {
			t.Fatalf("expected NOT candidate ext: %q", n)
		}
	}
}

func TestKindClassifiersBogus(t *testing.T) {
	bogus := ArtifactKind("bogus-not-an-enum")
	if IsCredentialKind(bogus) {
		t.Fatal("bogus must not be credential kind")
	}
	if IsInsiderInformationKind(bogus) {
		t.Fatal("bogus must not be insider kind")
	}
	if IsValuationIPKind(bogus) {
		t.Fatal("bogus must not be valuation IP kind")
	}
}

func TestPeriodFromFilenameValues(t *testing.T) {
	cases := map[string]string{
		"report_202606.pdf":   "202606", // YYYYMM
		"snapshot_202613.pdf": "2026",   // invalid month -> YYYY only
		"deal_2026_final.pdf": "2026",   // bare year
		"pitch_deck.pptx":     "",       // no year
		"old_1999_file.pdf":   "",       // pre-2000 not matched
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

// -- mergeFields --------------------------------------------------

func TestMergeFieldsComprehensive(t *testing.T) {
	c := &fileCollector{}
	body := []byte("Closing Memo - Project Tango\n" +
		"DRAFT - PRIVILEGED AND CONFIDENTIAL\n" +
		"password=hunter2\n" +
		"deal_id: DEAL-2026-0123\n" +
		"project_name: Project Tango\n" +
		"advisor_firm: Cohen IB\n" +
		"mandate_type: sell-side\n" +
		"stage: closing\n" +
		"enterprise_value: 50000000000\n" +
		"advisory_fee: 750000000\n" +
		"success_fee_bps: 125\n" +
		"target_cuit: 30-71234567-8\n" +
		"bidder_cuit: 30-99999999-1\n" +
		"cross-border\n" +
		"NYSE\n")
	row := Row{ArtifactKind: KindClosingMemo}
	c.mergeFields(&row, body)

	if !row.HasPasswordInConfig {
		t.Fatal("password must flag")
	}
	if !row.HasPreAnnouncementDraft {
		t.Fatal("DRAFT must flag")
	}
	if !row.HasCrossBorderTarget {
		t.Fatal("cross-border must flag")
	}
	if !row.HasPublicTarget {
		t.Fatal("NYSE must flag public target")
	}
	if row.DealID != "DEAL-2026-0123" {
		t.Fatalf("deal=%q", row.DealID)
	}
	if row.ProjectNameHash == "" {
		t.Fatal("project name must hash")
	}
	if row.AdvisorFirm != FirmCohenIB {
		t.Fatalf("firm=%q", row.AdvisorFirm)
	}
	if row.MandateType != MandateSellSide {
		t.Fatalf("mandate=%q", row.MandateType)
	}
	if row.DealStage != StageClosing {
		t.Fatalf("stage=%q", row.DealStage)
	}
	if row.EnterpriseValueARSMillions != 50_000 {
		t.Fatalf("EV=%d", row.EnterpriseValueARSMillions)
	}
	if row.AdvisoryFeeARSMillions != 750 {
		t.Fatalf("fee=%d", row.AdvisoryFeeARSMillions)
	}
	if row.SuccessFeeBPS != 125 {
		t.Fatalf("bps=%d", row.SuccessFeeBPS)
	}
	if row.TargetCuitPrefix != "30" || row.TargetCuitSuffix4 != "5678" {
		t.Fatalf("target cuit=(%q,%q)", row.TargetCuitPrefix, row.TargetCuitSuffix4)
	}
	if row.BidderCuitPrefix != "30" {
		t.Fatalf("bidder cuit prefix=%q", row.BidderCuitPrefix)
	}
}

func TestMergeFieldsCounts(t *testing.T) {
	c := &fileCollector{}

	rr := Row{ArtifactKind: KindBidderRoster}
	c.mergeFields(&rr, []byte("Bidder Roster\nbidder_count: 15\n"))
	if rr.BidderCount != 15 {
		t.Fatalf("bidder count=%d", rr.BidderCount)
	}

	dr := Row{ArtifactKind: KindDataroomManifest}
	c.mergeFields(&dr, []byte("Dataroom Manifest\ndataroom_file_count: 245\n"))
	if dr.DataroomFileCount != 245 {
		t.Fatalf("dataroom count=%d", dr.DataroomFileCount)
	}
}

func TestMergeFieldsIndividualCuitIgnored(t *testing.T) {
	c := &fileCollector{}
	row := Row{ArtifactKind: KindNDA}
	c.mergeFields(&row, []byte("NDA\n"+
		"target_cuit: 27-11111111-4\n"+
		"bidder_cuit: 20-22222222-3\n"))
	if row.TargetCuitPrefix != "" {
		t.Fatalf("individual target cuit must be ignored, got %q", row.TargetCuitPrefix)
	}
	if row.BidderCuitPrefix != "" {
		t.Fatalf("individual bidder cuit must be ignored, got %q", row.BidderCuitPrefix)
	}
}

func TestMergeFieldsAllKinds(t *testing.T) {
	c := &fileCollector{}
	body := []byte("deal_id: DEAL-2026-0777\nDRAFT\n")
	for _, k := range []ArtifactKind{
		KindPitchDeck, KindNDA, KindInformationMemorandum,
		KindDataroomManifest, KindBidderRoster, KindProcessLetter,
		KindBidEvaluation, KindDCFModel, KindLBOModel, KindMergerModel,
		KindQofEReport, KindSPADraft, KindDisclosureSchedules,
		KindClosingMemo, KindFairnessOpinion, KindSynergyAnalysis,
		KindAntitrustMemo, KindHechoRelevanteDraft, KindConfig,
		KindCredentials, KindInstaller, KindOther, KindUnknown,
	} {
		row := Row{ArtifactKind: k}
		c.mergeFields(&row, body)
		switch k {
		case KindInstaller, KindOther, KindUnknown:
			// early return: no deal id merged.
			if row.DealID != "" {
				t.Fatalf("kind %q must early-return, got deal=%q", k, row.DealID)
			}
		case KindPitchDeck, KindNDA, KindInformationMemorandum,
			KindDataroomManifest, KindBidderRoster, KindProcessLetter,
			KindBidEvaluation, KindDCFModel, KindLBOModel, KindMergerModel,
			KindQofEReport, KindSPADraft, KindDisclosureSchedules,
			KindClosingMemo, KindFairnessOpinion, KindSynergyAnalysis,
			KindAntitrustMemo, KindHechoRelevanteDraft, KindConfig,
			KindCredentials:
			if row.DealID != "DEAL-2026-0777" {
				t.Fatalf("kind %q deal id=%q", k, row.DealID)
			}
		}
	}
}

// -- consider (direct) --------------------------------------------

func TestConsiderDedup(t *testing.T) {
	c := &fileCollector{now: fixedNow}
	out := []Row{{FilePath: "/x/pitch_deck.pptx"}}
	c.consider("/x/pitch_deck.pptx", "", &out)
	if len(out) != 1 {
		t.Fatalf("dedup must skip, got %d", len(out))
	}
}

func TestConsiderStatError(t *testing.T) {
	c := &fileCollector{
		statFile: func(string) (os.FileInfo, error) { return nil, errors.New("boom") },
		now:      fixedNow,
	}
	var out []Row
	c.consider("/x/pitch_deck.pptx", "", &out)
	if len(out) != 0 {
		t.Fatalf("stat error must not append, got %d", len(out))
	}
}

func TestConsiderInstallerHashOnly(t *testing.T) {
	body := []byte("MSI ib_ installer payload deal")
	c := &fileCollector{
		readFile: func(string) ([]byte, error) { return body, nil },
		statFile: func(string) (os.FileInfo, error) {
			return fakeFileInfo{
				name: "ib_setup.msi",
				size: int64(len(body)),
				mode: 0o644,
				mod:  fixedNow(),
			}, nil
		},
		now: fixedNow,
	}
	var out []Row
	c.consider("/x/ib_setup.msi", "alice", &out)
	if len(out) != 1 {
		t.Fatalf("want 1 row, got %d", len(out))
	}
	r := out[0]
	if r.ArtifactKind != KindInstaller {
		t.Fatalf("kind=%q want installer", r.ArtifactKind)
	}
	if r.FileHash == "" {
		t.Fatal("installer must still hash body")
	}
	if r.DealID != "" {
		t.Fatal("installer must not parse fields")
	}
	if !r.IsRecent {
		t.Fatal("modtime == clock must be recent")
	}
}

func TestConsiderReadFileError(t *testing.T) {
	c := &fileCollector{
		readFile: func(string) ([]byte, error) { return nil, errors.New("unreadable") },
		statFile: func(string) (os.FileInfo, error) {
			return fakeFileInfo{
				name: "pitch_deck.pptx",
				size: 10,
				mode: 0o644,
				mod:  fixedNow(),
			}, nil
		},
		now: fixedNow,
	}
	var out []Row
	c.consider("/x/pitch_deck.pptx", "", &out)
	if len(out) != 1 {
		t.Fatalf("want 1 row, got %d", len(out))
	}
	if out[0].FileHash != "" {
		t.Fatal("read error must leave hash empty")
	}
}

func TestConsiderStaleNotRecent(t *testing.T) {
	body := []byte("Pitch Deck\nDRAFT\ndeal_id: DEAL-2026-0001\n")
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &fileCollector{
		readFile: func(string) ([]byte, error) { return body, nil },
		statFile: func(string) (os.FileInfo, error) {
			return fakeFileInfo{
				name: "pitch_deck.pptx",
				size: int64(len(body)),
				mode: 0o644,
				mod:  old,
			}, nil
		},
		now: fixedNow,
	}
	var out []Row
	c.consider("/x/pitch_deck.pptx", "bob", &out)
	if len(out) != 1 {
		t.Fatalf("want 1 row, got %d", len(out))
	}
	if out[0].IsRecent {
		t.Fatal("2020 file must not be recent under 2026 clock")
	}
	if out[0].FileHash == "" {
		t.Fatal("readable body must hash")
	}
}

// -- Collect (missing install root, empty) ------------------------

func TestCollectEmptyReturnsNoRows(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-ma-root"},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedNow,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateSecurityAllKindsAutoFlag(t *testing.T) {
	cases := []struct {
		get  func(Row) bool
		kind ArtifactKind
	}{
		{func(r Row) bool { return r.HasPitchDeck }, KindPitchDeck},
		{func(r Row) bool { return r.HasNDA }, KindNDA},
		{func(r Row) bool { return r.HasInformationMemorandum }, KindInformationMemorandum},
		{func(r Row) bool { return r.HasDataroomManifest }, KindDataroomManifest},
		{func(r Row) bool { return r.HasBidderRoster }, KindBidderRoster},
		{func(r Row) bool { return r.HasProcessLetter }, KindProcessLetter},
		{func(r Row) bool { return r.HasBidEvaluation }, KindBidEvaluation},
		{func(r Row) bool { return r.HasDCFModel }, KindDCFModel},
		{func(r Row) bool { return r.HasLBOModel }, KindLBOModel},
		{func(r Row) bool { return r.HasMergerModel }, KindMergerModel},
		{func(r Row) bool { return r.HasQofEReport }, KindQofEReport},
		{func(r Row) bool { return r.HasSPADraft }, KindSPADraft},
		{func(r Row) bool { return r.HasDisclosureSchedules }, KindDisclosureSchedules},
		{func(r Row) bool { return r.HasClosingMemo }, KindClosingMemo},
		{func(r Row) bool { return r.HasFairnessOpinion }, KindFairnessOpinion},
		{func(r Row) bool { return r.HasSynergyAnalysis }, KindSynergyAnalysis},
		{func(r Row) bool { return r.HasAntitrustMemo }, KindAntitrustMemo},
		{func(r Row) bool { return r.HasHechoRelevanteDraft }, KindHechoRelevanteDraft},
	}
	for _, tc := range cases {
		r := Row{ArtifactKind: tc.kind, FileMode: 0o644}
		AnnotateSecurity(&r)
		if !tc.get(r) {
			t.Fatalf("kind %q must auto-flag", tc.kind)
		}
	}
}

func TestAnnotateSecurityNoAutoFlagKinds(t *testing.T) {
	for _, k := range []ArtifactKind{
		KindConfig, KindCredentials, KindInstaller, KindOther, KindUnknown,
	} {
		r := Row{ArtifactKind: k, FileMode: 0o644}
		AnnotateSecurity(&r)
		if r.HasPitchDeck || r.HasNDA || r.HasDCFModel || r.HasSPADraft {
			t.Fatalf("kind %q must not auto-flag deal kinds", k)
		}
	}
}

func TestAnnotateSecurityModes(t *testing.T) {
	// world + group readable (0o644): insider kind flags.
	w := Row{ArtifactKind: KindSPADraft, FileMode: 0o644}
	AnnotateSecurity(&w)
	if !w.IsWorldReadable {
		t.Fatal("0o644 must be world readable")
	}
	if !w.IsGroupReadable {
		t.Fatal("0o644 must be group readable")
	}
	if !w.IsInsiderInformationRisk {
		t.Fatal("readable + SPA = insider info")
	}

	// group readable only (0o640): valuation kind flags.
	g := Row{ArtifactKind: KindDCFModel, FileMode: 0o640}
	AnnotateSecurity(&g)
	if g.IsWorldReadable {
		t.Fatal("0o640 must not be world readable")
	}
	if !g.IsGroupReadable {
		t.Fatal("0o640 must be group readable")
	}
	if !g.IsValuationIPRisk {
		t.Fatal("group-readable + DCF = valuation IP")
	}

	// locked down (0o600): no risk despite insider kind.
	l := Row{ArtifactKind: KindSPADraft, FileMode: 0o600}
	AnnotateSecurity(&l)
	if l.IsWorldReadable || l.IsGroupReadable {
		t.Fatal("0o600 must not be readable")
	}
	if l.IsInsiderInformationRisk || l.IsCredentialExposureRisk || l.IsValuationIPRisk {
		t.Fatalf("0o600 must carry no risk flags: %+v", l)
	}
	if !l.HasSPADraft {
		t.Fatal("auto-flag is independent of mode")
	}

	// mode 0 short-circuits the readable computation entirely.
	z := Row{ArtifactKind: KindDCFModel, FileMode: 0}
	AnnotateSecurity(&z)
	if z.IsWorldReadable || z.IsGroupReadable {
		t.Fatal("mode 0 must not be readable")
	}
	if z.IsValuationIPRisk {
		t.Fatal("mode 0 must carry no valuation risk")
	}
}

func TestAnnotateSecurityExposureAndCuit(t *testing.T) {
	r := Row{
		ArtifactKind:      KindBidderRoster,
		FileMode:          0o644,
		TargetCuitPrefix:  "30",
		TargetCuitSuffix4: "5678",
		BidderCuitPrefix:  "33",
		BidderCuitSuffix4: "1234",
	}
	AnnotateSecurity(&r)
	if !r.HasTargetCuit {
		t.Fatal("target cuit prefix must flag")
	}
	if !r.HasBidderCuit {
		t.Fatal("bidder cuit prefix must flag")
	}
	if !r.HasBidderRoster {
		t.Fatal("bidder roster kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + roster + cuit = credential exposure")
	}
	if !r.IsInsiderInformationRisk {
		t.Fatal("bidder roster is an insider kind")
	}
}

func TestAnnotateSecurityDraftInsider(t *testing.T) {
	r := Row{ArtifactKind: KindNDA, FileMode: 0o644, HasPreAnnouncementDraft: true}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + draft marker = insider even for NDA")
	}
}
