package filefingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- enum strings -------------------------------------------------

func TestSeverityEnumStrings(t *testing.T) {
	assert.Equal(t, "info", string(SeverityInfo))
	assert.Equal(t, "low", string(SeverityLow))
	assert.Equal(t, "medium", string(SeverityMedium))
	assert.Equal(t, "high", string(SeverityHigh))
	assert.Equal(t, "critical", string(SeverityCritical))
}

func TestCategoryEnumStrings(t *testing.T) {
	assert.Equal(t, "vcs", string(CategoryVCS))
	assert.Equal(t, "secrets", string(CategorySecrets))
	assert.Equal(t, "config", string(CategoryConfig))
	assert.Equal(t, "manifest", string(CategoryManifest))
	assert.Equal(t, "backup", string(CategoryBackup))
	assert.Equal(t, "admin", string(CategoryAdmin))
	assert.Equal(t, "well-known", string(CategoryWellKnown))
	assert.Equal(t, "debug", string(CategoryDebug))
	assert.Equal(t, "ide", string(CategoryIDE))
	assert.Equal(t, "docs", string(CategoryDocs))
	assert.Equal(t, "generic", string(CategoryGeneric))
	assert.Equal(t, 64*1024, MaxBodyBytes)
}

// -- severityRank / SortFindings ----------------------------------

func TestSeverityRank(t *testing.T) {
	assert.Equal(t, 5, severityRank(SeverityCritical))
	assert.Equal(t, 4, severityRank(SeverityHigh))
	assert.Equal(t, 3, severityRank(SeverityMedium))
	assert.Equal(t, 2, severityRank(SeverityLow))
	assert.Equal(t, 1, severityRank(SeverityInfo))
	assert.Equal(t, 0, severityRank(Severity("bogus")))
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{Path: "/robots.txt", Severity: SeverityInfo},
		{Path: "/.git/HEAD", Severity: SeverityCritical},
		{Path: "/b", Severity: SeverityMedium},
		{Path: "/a", Severity: SeverityMedium}, // same severity → path tiebreak
	}
	SortFindings(fs)
	assert.Equal(t, "/.git/HEAD", fs[0].Path) // critical first
	assert.Equal(t, SeverityMedium, fs[1].Severity)
	assert.Equal(t, "/a", fs[1].Path) // path asc within medium
	assert.Equal(t, "/b", fs[2].Path)
	assert.Equal(t, "/robots.txt", fs[3].Path) // info last
}

// -- statusAllowed ------------------------------------------------

func TestStatusAllowed(t *testing.T) {
	// Empty allow list → default 2xx range.
	assert.True(t, statusAllowed(200, nil))
	assert.True(t, statusAllowed(204, nil))
	assert.True(t, statusAllowed(299, nil))
	assert.False(t, statusAllowed(300, nil))
	assert.False(t, statusAllowed(199, nil))
	assert.False(t, statusAllowed(404, nil))

	// Explicit list.
	allow := []int{200, 302, 401}
	assert.True(t, statusAllowed(302, allow))
	assert.True(t, statusAllowed(401, allow))
	assert.False(t, statusAllowed(200, []int{302}))
	assert.False(t, statusAllowed(500, allow))
}

// -- truncate -----------------------------------------------------

func TestTruncate(t *testing.T) {
	assert.Equal(t, "short", truncate("short", 64))
	assert.Equal(t, "abc", truncate("abc", 3)) // exactly n → no ellipsis
	long := strings.Repeat("x", 70)
	got := truncate(long, 64)
	assert.Equal(t, strings.Repeat("x", 64)+"...", got)
}

// -- MatchProbe ---------------------------------------------------

func TestMatchProbeStatusRejected(t *testing.T) {
	p := Probe{ExpectedStatus: []int{200}}
	ok, ev := MatchProbe(p, 404, "anything")
	assert.False(t, ok)
	assert.Nil(t, ev)
}

func TestMatchProbeStatusOnly(t *testing.T) {
	p := Probe{ExpectedStatus: []int{200}}
	ok, ev := MatchProbe(p, 200, "irrelevant")
	assert.True(t, ok)
	assert.Empty(t, ev) // status-only match carries no evidence
}

func TestMatchProbeBodyContains(t *testing.T) {
	p := Probe{ExpectedStatus: []int{200}, BodyContains: "PHP Version"}
	ok, ev := MatchProbe(p, 200, "prefix PHP Version 8.2 suffix")
	require.True(t, ok)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "body contains PHP Version")

	ok, ev = MatchProbe(p, 200, "no marker here")
	assert.False(t, ok)
	assert.Nil(t, ev)
}

func TestMatchProbeBodyContainsEvidenceTruncated(t *testing.T) {
	needle := strings.Repeat("A", 100)
	p := Probe{ExpectedStatus: []int{200}, BodyContains: needle}
	ok, ev := MatchProbe(p, 200, "x"+needle+"y")
	require.True(t, ok)
	require.Len(t, ev, 1)
	assert.True(t, strings.HasSuffix(ev[0], "..."), "long needle evidence should be truncated: %q", ev[0])
}

func TestMatchProbeBodyRegex(t *testing.T) {
	p := Probe{ExpectedStatus: []int{200}, BodyRegex: regexp.MustCompile(`^ref:\s+refs/`)}
	ok, ev := MatchProbe(p, 200, "ref: refs/heads/main\n")
	require.True(t, ok)
	require.Len(t, ev, 1)
	assert.Equal(t, "body matches regex", ev[0])

	ok, _ = MatchProbe(p, 200, "not a git head")
	assert.False(t, ok)
}

func TestMatchProbeMustNotContain(t *testing.T) {
	p := Probe{
		ExpectedStatus: []int{200},
		BodyRegex:      regexp.MustCompile(`(?i)SECRET\s*=`),
		MustNotContain: "<html",
	}
	// Regex matches but the HTML guard trips → rejected (SPA false positive).
	ok, _ := MatchProbe(p, 200, "<html>SECRET=leak</html>")
	assert.False(t, ok)

	// Same body without the guard token → accepted.
	ok, ev := MatchProbe(p, 200, "SECRET=leak")
	assert.True(t, ok)
	assert.NotEmpty(t, ev)
}

func TestMatchProbeContainsAndRegexBothRequired(t *testing.T) {
	p := Probe{
		ExpectedStatus: []int{200},
		BodyContains:   "needle",
		BodyRegex:      regexp.MustCompile(`\d{3}`),
	}
	// Contains hit but regex miss → overall miss.
	ok, _ := MatchProbe(p, 200, "needle without digits")
	assert.False(t, ok)

	// Both hit → match with two evidence entries.
	ok, ev := MatchProbe(p, 200, "needle 123")
	require.True(t, ok)
	assert.Len(t, ev, 2)
}

// -- DefaultCatalog integrity -------------------------------------

func TestDefaultCatalogIntegrity(t *testing.T) {
	cat := DefaultCatalog()
	require.NotEmpty(t, cat)
	validSev := map[Severity]bool{
		SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
		SeverityHigh: true, SeverityCritical: true,
	}
	seen := map[string]bool{}
	for _, p := range cat {
		assert.Truef(t, strings.HasPrefix(p.Path, "/"), "path must be absolute: %q", p.Path)
		assert.NotEmptyf(t, p.Description, "probe %q missing description", p.Path)
		assert.Truef(t, validSev[p.Severity], "probe %q has bad severity %q", p.Path, p.Severity)
		assert.NotEmptyf(t, p.Category, "probe %q missing category", p.Path)
		assert.Falsef(t, seen[p.Path], "duplicate probe path %q", p.Path)
		seen[p.Path] = true
	}
	// Spot-check a known critical entry survives.
	assert.True(t, seen["/.git/HEAD"])
	assert.True(t, seen["/.env"])
}

// -- Scanner ------------------------------------------------------

func TestNewScannerDefaults(t *testing.T) {
	s := NewScanner(nil, nil)
	require.NotNil(t, s)
	assert.NotNil(t, s.client)
	assert.NotEmpty(t, s.probes) // defaults to DefaultCatalog
	assert.Equal(t, DefaultMaxConcurrent, s.maxC)
}

func TestSetMaxConcurrent(t *testing.T) {
	s := NewScanner(nil, []Probe{})
	s.SetMaxConcurrent(3)
	assert.Equal(t, 3, s.maxC)
	s.SetMaxConcurrent(0) // non-positive → reset to default
	assert.Equal(t, DefaultMaxConcurrent, s.maxC)
	s.SetMaxConcurrent(-5)
	assert.Equal(t, DefaultMaxConcurrent, s.maxC)
}

func TestDefaultClientRefusesRedirects(t *testing.T) {
	c := defaultClient()
	require.NotNil(t, c.CheckRedirect)
	err := c.CheckRedirect(nil, nil)
	assert.Equal(t, http.ErrUseLastResponse, err)
}

func TestScanNilBase(t *testing.T) {
	s := NewScanner(nil, []Probe{})
	_, err := s.Scan(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil base url")
}

func TestScanUnsupportedScheme(t *testing.T) {
	s := NewScanner(nil, []Probe{})
	u, _ := url.Parse("ftp://example.com/")
	_, err := s.Scan(context.Background(), u)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scheme")
}

func TestScanContextCancelled(t *testing.T) {
	s := NewScanner(nil, DefaultCatalog())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u, _ := url.Parse("http://127.0.0.1:1/")
	_, err := s.Scan(ctx, u)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ctx cancelled")
}

func TestScanMatchesAndSorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			_, _ = w.Write([]byte("DB_PASSWORD=hunter2\nAPI_KEY=abc\n"))
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	probes := []Probe{
		{
			Path: "/robots.txt", Description: "robots", Category: CategoryWellKnown,
			Severity: SeverityInfo, ExpectedStatus: []int{200},
			BodyContains: "User-agent:",
		},
		{
			Path: "/.env", Description: "env leak", Category: CategorySecrets,
			Severity: SeverityCritical, ExpectedStatus: []int{200},
			BodyRegex: regexp.MustCompile(`(?i)(DB_|API_KEY)\s*=`), MustNotContain: "<html",
		},
		{
			Path: "/missing", Description: "not there", Category: CategoryGeneric,
			Severity: SeverityLow, ExpectedStatus: []int{200},
		},
	}
	s := NewScanner(srv.Client(), probes)
	s.SetMaxConcurrent(2)

	base, err := url.Parse(srv.URL + "/some/prefix?ignored=1")
	require.NoError(t, err)
	res, err := s.Scan(context.Background(), base)
	require.NoError(t, err)

	assert.Equal(t, srv.URL, res.Endpoint) // trimURL strips path/query
	require.Len(t, res.Findings, 2)        // /missing 404 → no finding

	// Sorted: critical (.env) before info (robots).
	assert.Equal(t, "/.env", res.Findings[0].Path)
	assert.Equal(t, SeverityCritical, res.Findings[0].Severity)
	assert.Equal(t, 200, res.Findings[0].StatusCode)
	assert.Equal(t, srv.URL+"/.env", res.Findings[0].URL)
	assert.NotEmpty(t, res.Findings[0].Evidence)

	assert.Equal(t, "/robots.txt", res.Findings[1].Path)
	assert.Equal(t, SeverityInfo, res.Findings[1].Severity)
}

func TestScanFetchErrorsAreSilent(t *testing.T) {
	// No server: connection refused on every probe → zero findings, no error.
	probes := []Probe{
		{Path: "/.env", Description: "env", Category: CategorySecrets, Severity: SeverityCritical, ExpectedStatus: []int{200}},
	}
	s := NewScanner(nil, probes)
	u, _ := url.Parse("http://127.0.0.1:1/")
	res, err := s.Scan(context.Background(), u)
	require.NoError(t, err)
	assert.Empty(t, res.Findings)
}

func TestTrimURL(t *testing.T) {
	u, _ := url.Parse("https://example.com:8443/deep/path?q=1#frag")
	assert.Equal(t, "https://example.com:8443", trimURL(u))

	u2, _ := url.Parse("http://example.com/")
	assert.Equal(t, "http://example.com", trimURL(u2))
}
