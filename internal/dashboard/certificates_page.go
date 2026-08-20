// Certificates page — the fleet-identity view: which machines can prove
// they're yours, and which identities need attention.
//
// Two data sources with different availability, rendered as two sections:
//
//   - "This computer": read from agent.pem on local disk. Needs no platform
//     session, so it renders in EVERY page state — sign-in gates the tenant
//     inventory, never the local identity. When the inventory is available,
//     the disk fingerprint is cross-checked against the PKI-active record
//     (match / drift / unverified).
//   - Tenant inventory: the PKI list endpoint, behind the operator session.
//     Rows get derived lifecycle states (expiring ≤30d, expired-but-PKI-
//     still-says-active) on top of the four stored statuses, sorted
//     attention-first, with rotation history collapsed by default.
//
// Page states: populated · sign-in required · session expired (stale table
// kept, time-stamped) · PKI unreachable · empty tenant · unavailable mode.
// Filters and the history toggle live in the URL so views are bookmarkable.
package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// certExpiringWindow is the "expiring soon" horizon: PKI issues 90-day
// certificates, so 30 days marks the renewal window without crying wolf.
const certExpiringWindow = 30 * 24 * time.Hour

// certHorizonDays is the renewal-horizon strip's span.
const certHorizonDays = 90

// Lifecycle state keys, ordered by how urgently an operator must react.
const (
	certStateRevoked    = "revoked"
	certStateLag        = "lag" // stored active, but not_after has passed
	certStateExpired    = "expired"
	certStateExpiring   = "expiring"
	certStateActive     = "active"
	certStateUnknown    = "unknown"
	certStateSuperseded = "superseded"
)

// certStateRank orders inventory rows attention-first.
var certStateRank = map[string]int{
	certStateRevoked:    0,
	certStateLag:        1,
	certStateExpired:    2,
	certStateExpiring:   3,
	certStateActive:     4,
	certStateUnknown:    5,
	certStateSuperseded: 6,
}

// certRowView is one inventory row with its derived lifecycle state.
type certRowView struct {
	pkiCertificateSummary
	StateKey   string
	BadgeLabel string
	BadgeClass string
	BadgeNote  string // secondary line under the badge (revocation age, lag explainer)
	ExpiresRel string // "in 12d" / "14d ago" / "—"
	ExpiresAbs string // "2026-10-19"
	IssuedAbs  string
	ShortFP    string // abbreviated SHA-256 fingerprint for the table cell
	Attention  bool
	IsLocal    bool
	IsHistory  bool
}

// certLocalIdentity is the "This computer" card, read from disk.
type certLocalIdentity struct {
	AgentCode       string
	HasCert         bool
	NotAfter        string
	DaysLeft        int
	Expired         bool
	Fingerprint     string // short display form
	FingerprintFull string
	SubjectCN       string
	CertsDir        string
	ReadError       string
	// PKIMatch: "match" | "drift" | "unverified" | "absent" | "" (no local cert)
	PKIMatch       string
	PKIActiveShort string // PKI-active fingerprint when drifting
	GaugePct       int    // 0–100 of validity remaining, for the ring
}

// certPageMode is the page-level state.
const (
	certModePopulated   = "populated"
	certModeEmpty       = "empty"
	certModeSignIn      = "signin"
	certModeSessionGone = "session-expired"
	certModeError       = "error"
	certModeUnavailable = "unavailable"
)

type certCounts struct {
	Active   int
	Expiring int
	Expired  int // includes status-lag rows
	Revoked  int
	History  int
}

type certificatesView struct {
	GeneratedAt string
	Tenant      string
	Mode        string
	Error       string
	SignInURL   string
	Local       certLocalIdentity
	Counts      certCounts
	Rows        []certRowView
	Total       int
	Hidden      int // superseded rows collapsed behind the history toggle
	ShowHistory bool
	Filter      string
	Paused      bool
	StaleAt     string // "15:04" when Mode == session-expired and rows are cached
	HorizonSVG  template.HTML
	WrapperURL  string
	ToggleURL   string // pause/resume
	HistoryURL  string
	ChipURL     func(filter string) string `json:"-"`
}

// certInventoryCache keeps the last successfully fetched inventory so a
// session that expires mid-use degrades to a time-stamped stale table
// instead of a blank page.
type certInventoryCache struct {
	mu        sync.Mutex
	rows      []pkiCertificateSummary
	fetchedAt time.Time
}

func (c *certInventoryCache) store(rows []pkiCertificateSummary) {
	c.mu.Lock()
	c.rows = append(c.rows[:0:0], rows...)
	c.fetchedAt = time.Now()
	c.mu.Unlock()
}

func (c *certInventoryCache) last() ([]pkiCertificateSummary, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rows) == 0 {
		return nil, time.Time{}, false
	}
	return append([]pkiCertificateSummary(nil), c.rows...), c.fetchedAt, true
}

// -------------------------------------------------------------------------
// Derivation
// -------------------------------------------------------------------------

// parsePKITime accepts the timestamp shapes the PKI API has emitted across
// versions: RFC3339(Nano) and ClickHouse DateTime64 without a zone.
func parsePKITime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05.999", "2006-01-02 15:04:05.999", "2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// deriveCertState maps a stored PKI status + the clock onto the seven
// lifecycle states. The two derived states exist because the stored status
// alone hides what operators most need: "active" with not_after in the past
// is already failing mTLS (status lag), and "active" inside the renewal
// window deserves an amber flag before it becomes an incident.
func deriveCertState(c pkiCertificateSummary, now time.Time) (stateKey, label, badgeClass, note string) {
	notAfter, hasNotAfter := parsePKITime(c.NotAfter)
	switch strings.ToLower(strings.TrimSpace(c.Status)) {
	case "active", "valid":
		if hasNotAfter {
			if now.After(notAfter) {
				return certStateLag, "expired · status lag", "badge-red", "PKI still says active"
			}
			if notAfter.Sub(now) <= certExpiringWindow {
				return certStateExpiring, "expiring", "badge-yellow", ""
			}
		}
		return certStateActive, "active", "badge-green", ""
	case "expired":
		return certStateExpired, "expired", "badge-expired", "renewal missed"
	case "revoked":
		return certStateRevoked, "revoked", "badge-revoked", ""
	case "superseded", "renewed":
		return certStateSuperseded, "superseded", "badge-gray", ""
	}
	if s := strings.TrimSpace(c.Status); s != "" {
		return certStateUnknown, s, "badge-gray", ""
	}
	return certStateUnknown, "unknown", "badge-gray", ""
}

func certRelativeDays(t time.Time, now time.Time) string {
	d := t.Sub(now)
	days := int(d.Hours() / 24)
	switch {
	case d >= 0 && days == 0:
		return "today"
	case d >= 0:
		return fmt.Sprintf("in %dd", days)
	case -days == 0:
		return "today"
	default:
		return fmt.Sprintf("%dd ago", -days)
	}
}

func certDateOnly(s string) string {
	if t, ok := parsePKITime(s); ok {
		return t.UTC().Format("2006-01-02")
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// normalizeFingerprint makes disk- and PKI-computed SHA-256 fingerprints
// comparable regardless of case, colons, or a sha256: prefix.
func normalizeFingerprint(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.TrimPrefix(fp, "sha256:")
	return strings.ReplaceAll(fp, ":", "")
}

// shortCertFingerprint abbreviates a normalized SHA-256 fingerprint for
// table cells (head…tail so two certs rarely collide visually).
func shortCertFingerprint(fp string) string {
	fp = normalizeFingerprint(fp)
	if len(fp) > 12 {
		return fp[:4] + "…" + fp[len(fp)-4:]
	}
	return fp
}

// buildCertRows derives, sorts (attention first, then soonest expiry), and
// annotates the tenant inventory.
func buildCertRows(rows []pkiCertificateSummary, localAgentCode string, now time.Time) ([]certRowView, certCounts) {
	out := make([]certRowView, 0, len(rows))
	var counts certCounts
	for _, c := range rows {
		state, label, class, note := deriveCertState(c, now)
		v := certRowView{
			pkiCertificateSummary: c,
			StateKey:              state,
			BadgeLabel:            label,
			BadgeClass:            class,
			BadgeNote:             note,
			ExpiresAbs:            certDateOnly(c.NotAfter),
			IssuedAbs:             certDateOnly(c.IssuedAt),
			ShortFP:               shortCertFingerprint(c.FingerprintSHA256),
			IsLocal:               localAgentCode != "" && strings.EqualFold(strings.TrimSpace(c.AgentCode), localAgentCode),
			IsHistory:             state == certStateSuperseded,
		}
		if notAfter, ok := parsePKITime(c.NotAfter); ok && state != certStateRevoked && state != certStateSuperseded {
			v.ExpiresRel = certRelativeDays(notAfter, now)
		} else {
			v.ExpiresRel = "—"
		}
		switch state {
		case certStateRevoked, certStateLag, certStateExpired:
			v.Attention = true
		}
		switch state {
		case certStateActive:
			counts.Active++
		case certStateExpiring:
			counts.Expiring++
			counts.Active++ // an expiring cert is still an active cert
		case certStateExpired, certStateLag:
			counts.Expired++
		case certStateRevoked:
			counts.Revoked++
		case certStateSuperseded:
			counts.History++
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := certStateRank[out[i].StateKey], certStateRank[out[j].StateKey]
		if ri != rj {
			return ri < rj
		}
		ti, iok := parsePKITime(out[i].NotAfter)
		tj, jok := parsePKITime(out[j].NotAfter)
		if iok && jok && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i].AgentCode < out[j].AgentCode
	})
	return out, counts
}

// buildCertLocalIdentity reads this machine's identity from agent.pem in the
// certs dir — no session, no network.
func buildCertLocalIdentity(certsDir string, now time.Time) certLocalIdentity {
	local := certLocalIdentity{AgentCode: kiteAgentCode(), CertsDir: certsDir}
	if certsDir == "" {
		return local
	}
	raw, err := os.ReadFile(filepath.Join(certsDir, "agent.pem")) //#nosec G304 -- certs dir is operator-configured
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			local.ReadError = err.Error()
		}
		return local
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		local.ReadError = "agent.pem contains no PEM block"
		return local
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		local.ReadError = "parse agent.pem: " + err.Error()
		return local
	}
	sum := sha256.Sum256(cert.Raw)
	local.HasCert = true
	local.FingerprintFull = hex.EncodeToString(sum[:])
	local.Fingerprint = shortCertFingerprint(local.FingerprintFull)
	local.SubjectCN = cert.Subject.CommonName
	local.NotAfter = cert.NotAfter.UTC().Format("2006-01-02")
	local.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	local.Expired = now.After(cert.NotAfter)
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total > 0 {
		pct := int(float64(cert.NotAfter.Sub(now)) / float64(total) * 100)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		local.GaugePct = pct
	}
	return local
}

// crossCheckLocalIdentity compares the on-disk fingerprint with the PKI
// record that is active for this agent code. Detects drift the agent itself
// cannot see: a revocation behind its back, or a renewal that never landed.
func crossCheckLocalIdentity(local *certLocalIdentity, rows []certRowView) {
	if !local.HasCert {
		return
	}
	diskFP := normalizeFingerprint(local.FingerprintFull)
	var pkiActive *certRowView
	for i := range rows {
		if !rows[i].IsLocal {
			continue
		}
		if rows[i].StateKey == certStateActive || rows[i].StateKey == certStateExpiring || rows[i].StateKey == certStateLag {
			pkiActive = &rows[i]
			break // rows are attention-sorted; first active-ish local row wins
		}
	}
	if pkiActive == nil {
		local.PKIMatch = "absent"
		return
	}
	if normalizeFingerprint(pkiActive.FingerprintSHA256) == diskFP {
		local.PKIMatch = "match"
		return
	}
	local.PKIMatch = "drift"
	local.PKIActiveShort = shortCertFingerprint(pkiActive.FingerprintSHA256)
}

// renewalHorizonSVG renders the next-90-days expiry strip: one dot per
// weekly bucket of active/expiring certificates, sized by count, amber
// inside the renewal window. Safe by construction — numeric geometry only.
func renewalHorizonSVG(rows []certRowView, now time.Time) template.HTML {
	buckets := make([]int, certHorizonDays/7+1)
	total := 0
	for _, r := range rows {
		if r.StateKey != certStateActive && r.StateKey != certStateExpiring {
			continue
		}
		notAfter, ok := parsePKITime(r.NotAfter)
		if !ok {
			continue
		}
		days := int(notAfter.Sub(now).Hours() / 24)
		if days < 0 || days > certHorizonDays {
			continue
		}
		buckets[days/7]++
		total++
	}
	if total == 0 {
		return ""
	}
	const width, height = 900, 46
	var b strings.Builder
	// Intrinsic width/height keep the strip icon-sized even when a stale
	// build serves this markup without the page's CSS — a viewBox-only SVG
	// would otherwise balloon to the container width.
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" height="%d" preserveAspectRatio="none" role="img" aria-label="certificate expiries over the next %d days">`,
		width, height, height, certHorizonDays)
	b.WriteString(`<line x1="0" y1="30" x2="900" y2="30" stroke="currentColor" stroke-opacity="0.25" stroke-width="1.5"/>`)
	for i, lbl := range []string{"today", "+30d", "+60d", "+90d"} {
		x := 4 + i*290
		anchor := "start"
		if i == 3 {
			x = width - 4
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%d" y="43" font-size="10" text-anchor="%s" fill="currentColor" fill-opacity="0.6">%s</text>`, x, anchor, lbl)
	}
	for i, n := range buckets {
		if n == 0 {
			continue
		}
		day := i*7 + 3 // bucket midpoint
		x := day * width / certHorizonDays
		r := 4 + n
		if r > 10 {
			r = 10
		}
		color := "#22c55e"
		if day <= 30 {
			color = "#e8a13d"
		}
		fmt.Fprintf(&b, `<circle cx="%d" cy="30" r="%d" fill="%s" fill-opacity="0.9"/>`, x, r, color)
		fmt.Fprintf(&b, `<text x="%d" y="14" font-size="10" text-anchor="middle" fill="%s" font-weight="700">%d</text>`, x, color, n)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //#nosec G203 -- numeric geometry and fixed color literals only
}

// -------------------------------------------------------------------------
// View assembly
// -------------------------------------------------------------------------

type certPageParams struct {
	ShowHistory bool
	Filter      string // "", active, expiring, expired, revoked, history
	Paused      bool
}

func parseCertPageParams(r *http.Request) certPageParams {
	q := r.URL.Query()
	filter := q.Get("filter")
	switch filter {
	case "active", "expiring", "expired", "revoked", "history":
	default:
		filter = ""
	}
	return certPageParams{
		ShowHistory: q.Get("history") == "1" || filter == "history",
		Filter:      filter,
		Paused:      q.Get("paused") == "1",
	}
}

func certFragmentURL(p certPageParams) string {
	q := url.Values{}
	if p.Filter != "" {
		q.Set("filter", p.Filter)
	}
	if p.ShowHistory && p.Filter != "history" {
		q.Set("history", "1")
	}
	if p.Paused {
		q.Set("paused", "1")
	}
	if enc := q.Encode(); enc != "" {
		return "/fragments/certificates?" + enc
	}
	return "/fragments/certificates"
}

func certPageURL(p certPageParams) string {
	return "/certificates" + strings.TrimPrefix(certFragmentURL(p), "/fragments/certificates")
}

func buildCertificatesView(ctx context.Context, deps onboardingDeps, cache *certInventoryCache, p certPageParams) certificatesView {
	now := time.Now()
	view := certificatesView{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		SignInURL:   "/kite-login?dashboard=" + url.QueryEscape(certPageURL(certPageParams{Filter: p.Filter, ShowHistory: p.ShowHistory})),
		Local:       buildCertLocalIdentity(deps.CertsDir, now),
		ShowHistory: p.ShowHistory,
		Filter:      p.Filter,
		Paused:      p.Paused,
		WrapperURL:  certFragmentURL(p),
	}
	toggled := p
	toggled.Paused = !p.Paused
	view.ToggleURL = certFragmentURL(toggled)
	hist := p
	hist.ShowHistory = !p.ShowHistory
	if hist.Filter == "history" {
		hist.Filter = ""
	}
	view.HistoryURL = certPageURL(hist)
	view.ChipURL = func(filter string) string {
		next := p
		if p.Filter == filter {
			filter = "" // clicking the active chip clears the filter
		}
		next.Filter = filter
		return certPageURL(next)
	}

	if deps.PKIReader == nil || deps.PKIOperatorToken == nil || strings.TrimSpace(deps.PKIEndpoint) == "" {
		view.Mode = certModeUnavailable
		if view.Local.HasCert {
			view.Local.PKIMatch = "unverified"
		}
		return view
	}

	token, err := deps.PKIOperatorToken(ctx)
	if err != nil {
		view.Mode = certModeSignIn
		if view.Local.HasCert {
			view.Local.PKIMatch = "unverified"
		}
		return view
	}

	inventory, _, err := deps.PKIReader.List(ctx, deps.PKIEndpoint, token)
	if err != nil {
		if view.Local.HasCert {
			view.Local.PKIMatch = "unverified"
		}
		if errors.Is(err, errPKICertificateSignInRequired) {
			if stale, at, ok := cache.last(); ok {
				view.Mode = certModeSessionGone
				view.StaleAt = at.Format("15:04")
				view.fillInventory(stale, now, p)
				return view
			}
			view.Mode = certModeSignIn
			view.Error = "Your VulnerTrack session expired — sign in again."
			return view
		}
		view.Mode = certModeError
		view.Error = err.Error()
		return view
	}

	cache.store(inventory)
	if len(inventory) == 0 {
		view.Mode = certModeEmpty
		if view.Local.HasCert {
			view.Local.PKIMatch = "absent"
		}
		return view
	}
	view.Mode = certModePopulated
	view.fillInventory(inventory, now, p)
	return view
}

// fillInventory derives rows, counts, tenant, horizon, and the local
// cross-check from a fetched (or cached) inventory.
func (v *certificatesView) fillInventory(inventory []pkiCertificateSummary, now time.Time, p certPageParams) {
	rows, counts := buildCertRows(inventory, v.Local.AgentCode, now)
	v.Counts = counts
	v.Total = len(rows)
	if v.Tenant == "" && len(rows) > 0 {
		v.Tenant = rows[0].TenantID
	}
	crossCheckLocalIdentity(&v.Local, rows)
	v.HorizonSVG = renewalHorizonSVG(rows, now)

	shown := make([]certRowView, 0, len(rows))
	hidden := 0
	for _, r := range rows {
		if p.Filter != "" {
			if !certRowMatchesFilter(r, p.Filter) {
				continue
			}
			shown = append(shown, r)
			continue
		}
		if r.IsHistory && !p.ShowHistory {
			hidden++
			continue
		}
		shown = append(shown, r)
	}
	v.Rows = shown
	v.Hidden = hidden
}

func certRowMatchesFilter(r certRowView, filter string) bool {
	switch filter {
	case "active":
		return r.StateKey == certStateActive || r.StateKey == certStateExpiring
	case "expiring":
		return r.StateKey == certStateExpiring
	case "expired":
		return r.StateKey == certStateExpired || r.StateKey == certStateLag
	case "revoked":
		return r.StateKey == certStateRevoked
	case "history":
		return r.StateKey == certStateSuperseded
	}
	return true
}

// -------------------------------------------------------------------------
// Rendering + routes
// -------------------------------------------------------------------------

func registerCertificatesRoutes(mux *http.ServeMux, deps onboardingDeps) {
	cache := &certInventoryCache{}

	mux.HandleFunc("GET /fragments/certificates", func(w http.ResponseWriter, r *http.Request) {
		view := buildCertificatesView(r.Context(), deps, cache, parseCertPageParams(r))
		renderOnboardingFragment(w, deps.Logger, "certificates", func(buf io.Writer) error {
			if err := certificatesFragmentTmpl.Execute(buf, view); err != nil {
				return fmt.Errorf("render certificates fragment: %w", err)
			}
			return nil
		})
	})

	// Detail drawer — the shared detail template wrapped in the app's
	// standard row-drawer chrome, with drawer-shaped errors.
	mux.HandleFunc("GET /fragments/certificates/{id}", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "certificate-drawer", func(buf io.Writer) error {
			return renderCertificateDrawer(r.Context(), buf, deps, strings.TrimSpace(r.PathValue("id")))
		})
	})
}

func renderCertificateDrawer(ctx context.Context, w io.Writer, deps onboardingDeps, certificateID string) error {
	writeErr := func(msg string) error {
		if err := certDrawerErrTmpl.Execute(w, msg); err != nil {
			return fmt.Errorf("render certificate drawer error: %w", err)
		}
		return nil
	}
	if _, err := uuid.Parse(certificateID); err != nil {
		return writeErr("Invalid certificate ID.")
	}
	if deps.PKIReader == nil || deps.PKIOperatorToken == nil {
		return writeErr("PKI certificate details are unavailable in this dashboard mode.")
	}
	token, err := deps.PKIOperatorToken(ctx)
	if err != nil {
		return writeErr("Sign in to VulnerTrack to inspect certificates.")
	}
	detail, err := deps.PKIReader.Get(ctx, deps.PKIEndpoint, token, certificateID)
	if err != nil {
		if errors.Is(err, errPKICertificateSignInRequired) {
			return writeErr("Your VulnerTrack session expired — sign in again.")
		}
		if deps.Logger != nil {
			deps.Logger.Error("certificates: load detail failed",
				"certificate_id", certificateID, "error", err)
		}
		return writeErr("Could not load the certificate from the PKI service.")
	}
	detail.StatusClass = pkiCertificateStatusClass(detail.Status)
	var body strings.Builder
	if execErr := pkiCertificateDetailTmpl.Execute(&body, detail); execErr != nil {
		return fmt.Errorf("render certificate detail: %w", execErr)
	}
	err = certDrawerTmpl.Execute(w, struct {
		Title string
		Body  template.HTML
	}{
		Title: strings.TrimSpace(detail.AgentCode + " " + detail.SubjectCN),
		// Body is the output of a trusted in-process html/template render.
		Body: template.HTML(body.String()), //#nosec G203 -- see comment
	})
	if err != nil {
		return fmt.Errorf("render certificate drawer: %w", err)
	}
	return nil
}
