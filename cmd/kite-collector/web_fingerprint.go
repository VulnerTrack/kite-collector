package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/customcatalog"
)

// newWebFingerprintCmd builds the `kite-collector web-fingerprint`
// subcommand. The command exposes the composite (TLS + header + JS +
// file + API) network fingerprint to an operator who wants to ask
// "what is the stack behind this URL?" without running the full
// discovery pipeline.
//
// The default `--output text` view renders the per-layer StackSummary
// produced by CompositeResult.Summarise() — one line per architectural
// layer (Hosting, WebServer, Runtime, Framework, Auth, Analytics,
// DataLayer) with cross-surface evidence credited to each pick. The
// `--output json` view prints the full CompositeResult plus the
// StackSummary so downstream tooling can consume both attributions and
// the synthesised view.
func newWebFingerprintCmd() *cobra.Command {
	var (
		target        string
		scanList      string
		output        string
		timeout       time.Duration
		sni           string
		skip          []string
		concurrency   int
		minConfidence string
		vendorFilter  string
		categories    []string
		summaryOnly   bool
		failOn        []string
		customCatalog string
	)

	cmd := &cobra.Command{
		Use:   "web-fingerprint",
		Short: "Identify the stack behind a URL (TLS + headers + JS + files + APIs)",
		Long: `Run a concurrent multi-surface fingerprint sweep against one URL
(or every URL in a newline-delimited file) and print the synthesised
stack: hosting/CDN, web server, runtime, framework, auth, analytics,
and data layer. Each pick lists the surfaces ("tls", "header", "api",
"js", "file") that agreed on it so the operator can confirm or
override the choice.`,
		Example: `  # Quick text summary of a public site
  kite-collector web-fingerprint --url https://example.com

  # Full JSON (every per-surface match) for downstream tooling
  kite-collector web-fingerprint --url https://example.com --output json

  # Skip the file surface (60+ probes) for a faster sweep
  kite-collector web-fingerprint --url https://example.com --skip file

  # Sweep a customer URL list and emit one JSON record per target
  kite-collector web-fingerprint --scan-list urls.txt --output json

  # Parallelise a large list (output order is still deterministic)
  kite-collector web-fingerprint --scan-list urls.txt --concurrency 8`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebFingerprint(webFingerprintOpts{
				target:        target,
				scanList:      scanList,
				output:        output,
				timeout:       timeout,
				sni:           sni,
				skip:          skip,
				concurrency:   concurrency,
				minConfidence: minConfidence,
				vendorFilter:  vendorFilter,
				categories:    categories,
				summaryOnly:   summaryOnly,
				failOn:        failOn,
				customCatalog: customCatalog,
			})
		},
	}

	cmd.Flags().StringVar(&target, "url", "", "URL to fingerprint (scheme + host + optional port)")
	cmd.Flags().StringVar(&scanList, "scan-list", "", "newline-delimited file of URLs ('-' = stdin); '#' starts a comment")
	cmd.Flags().StringVar(&output, "output", "text", "output format: text, json, csv, ndjson")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "per-mechanism timeout")
	cmd.Flags().StringVar(&sni, "tls-sni", "", "override SNI sent during TLS handshake (default = host)")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "mechanisms to skip (any of tls,header,js,file,api)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 1, "parallel scans for --scan-list (1 = sequential)")
	cmd.Flags().StringVar(&minConfidence, "min-confidence", "", "drop matches below this band (low, medium, high)")
	cmd.Flags().StringVar(&vendorFilter, "vendor", "", "keep only fingerprints whose vendor contains this substring (case-insensitive)")
	cmd.Flags().StringSliceVar(&categories, "category", nil, "keep only fingerprints in these categories (comma-separated)")
	cmd.Flags().BoolVar(&summaryOnly, "summary-only", false, "emit only the synthesised StackSummary (skip per-surface raw fingerprints)")
	cmd.Flags().StringSliceVar(&failOn, "fail-on", nil, "exit non-zero when any fingerprint in these categories is found (CI gating: e.g. --fail-on secret-leak)")
	cmd.Flags().StringVar(&customCatalog, "custom-catalog", "", "path to a YAML overlay file with operator-supplied signatures (api/header/js/file/tls)")

	return cmd
}

type webFingerprintOpts struct {
	target        string
	scanList      string
	output        string
	sni           string
	minConfidence string
	vendorFilter  string
	customCatalog string
	categories    []string
	skip          []string
	failOn        []string
	timeout       time.Duration
	concurrency   int
	summaryOnly   bool
}

// failTriggered reports whether any fingerprint in the supplied
// result falls in one of the --fail-on categories. Used to set a
// non-zero exit code so CI pipelines can gate on findings.
func (o webFingerprintOpts) failTriggered(res compositefingerprint.CompositeResult) bool {
	if len(o.failOn) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(o.failOn))
	for _, c := range o.failOn {
		want[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
	}
	hit := func(c string) bool {
		_, ok := want[strings.ToLower(c)]
		return ok
	}
	if res.TLS != nil {
		for _, fp := range res.TLS.Fingerprints {
			if hit(string(fp.Category)) {
				return true
			}
		}
	}
	if res.Header != nil {
		for _, fp := range res.Header.Fingerprints {
			if hit(string(fp.Category)) {
				return true
			}
		}
	}
	if res.JS != nil {
		for _, fp := range res.JS.Fingerprints {
			if hit(string(fp.Category)) {
				return true
			}
		}
	}
	if res.API != nil {
		for _, fp := range res.API.Fingerprints {
			if hit(string(fp.Category)) {
				return true
			}
		}
	}
	return false
}

// applyFilters runs every active --min-confidence / --vendor /
// --category filter against the raw composite result and returns the
// filtered copy. Empty filters are passthrough.
func (o webFingerprintOpts) applyFilters(raw compositefingerprint.CompositeResult) compositefingerprint.CompositeResult {
	r := raw.FilterByConfidence(o.minConfidence)
	r = r.FilterByVendor(o.vendorFilter)
	r = r.FilterByCategory(o.categories)
	return r
}

// runWebFingerprint validates the flags, runs one or more composite
// scans, and emits either a text StackSummary or JSON. Exactly one of
// --url and --scan-list must be set.
func runWebFingerprint(opts webFingerprintOpts) error {
	if opts.target == "" && opts.scanList == "" {
		return errors.New("must specify --url or --scan-list")
	}
	if opts.target != "" && opts.scanList != "" {
		return errors.New("--url and --scan-list are mutually exclusive")
	}

	options, err := buildCompositeOptions(opts)
	if err != nil {
		return err
	}
	if err = validateMinConfidence(opts.minConfidence); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	scanner, err := buildScanner(opts)
	if err != nil {
		return err
	}

	if opts.scanList != "" {
		return runWebFingerprintBatch(ctx, scanner, opts, options)
	}
	return runWebFingerprintSingle(ctx, scanner, opts, options)
}

// buildScanner constructs the composite scanner, layering in any
// operator-supplied YAML overlay from --custom-catalog. When no
// overlay is set the default scanner with each package's
// DefaultCatalog is used.
func buildScanner(opts webFingerprintOpts) (*compositefingerprint.Scanner, error) {
	if opts.customCatalog == "" {
		return compositefingerprint.NewScanner(), nil
	}
	cat, err := customcatalog.LoadFile(opts.customCatalog)
	if err != nil {
		return nil, fmt.Errorf("load custom catalog: %w", err)
	}
	return compositefingerprint.NewScannerWithCustomCatalogs(nil, compositefingerprint.CustomCatalogs{
		TLS:    cat.TLS,
		Header: cat.Header,
		JS:     cat.JS,
		File:   cat.File,
		API:    cat.API,
	}), nil
}

// validateMinConfidence rejects unknown bands early so the operator
// sees the error before a scan runs.
func validateMinConfidence(min string) error {
	switch strings.ToLower(strings.TrimSpace(min)) {
	case "", "low", "medium", "high":
		return nil
	default:
		return fmt.Errorf("--min-confidence must be low, medium, or high (got %q)", min)
	}
}

// buildCompositeOptions translates the CLI flags into a
// compositefingerprint.Options, validating --skip entries.
func buildCompositeOptions(opts webFingerprintOpts) (compositefingerprint.Options, error) {
	o := compositefingerprint.Options{
		PerMechanismTimeout: opts.timeout,
		TLSSNI:              opts.sni,
	}
	for _, s := range opts.skip {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "tls":
			o.DisableTLS = true
		case "header":
			o.DisableHeader = true
		case "js":
			o.DisableJS = true
		case "file":
			o.DisableFile = true
		case "api":
			o.DisableAPI = true
		case "":
		default:
			return o, fmt.Errorf("unknown --skip mechanism %q (want tls, header, js, file, or api)", s)
		}
	}
	return o, nil
}

func runWebFingerprintSingle(ctx context.Context, s *compositefingerprint.Scanner, opts webFingerprintOpts, options compositefingerprint.Options) error {
	scheme, host, port, err := splitWebTarget(opts.target)
	if err != nil {
		return err
	}
	raw, err := s.Scan(ctx, scheme, host, port, options)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	result := opts.applyFilters(raw)
	summary := result.Summarise()

	switch strings.ToLower(opts.output) {
	case "json":
		if err := writeWebFingerprintJSON(result, summary, opts.summaryOnly); err != nil {
			return err
		}
	case "ndjson":
		if err := writeWebFingerprintNDJSON(result, summary, opts.summaryOnly); err != nil {
			return err
		}
	case "csv":
		if err := writeWebFingerprintCSV(result.Endpoint, summary); err != nil {
			return err
		}
	case "text", "":
		writeWebFingerprintText(result, summary)
	default:
		return fmt.Errorf("unknown --output %q (want text, json, csv, or ndjson)", opts.output)
	}
	if opts.failTriggered(result) {
		return failOnHitError{categories: opts.failOn}
	}
	return nil
}

// failOnHitError is the sentinel error returned when --fail-on
// triggers. cobra sets a non-zero exit code for any RunE error; this
// type lets us format the message distinctly so operators see the
// gate fired rather than a regular failure.
type failOnHitError struct {
	categories []string
}

func (e failOnHitError) Error() string {
	return "fingerprint matched --fail-on categories: " + strings.Join(e.categories, ",")
}

// webBatchRecord holds one target's outcome for --scan-list. Per-target
// errors are kept so a single failure doesn't abort the rest.
type webBatchRecord struct {
	Result  *compositefingerprint.CompositeResult `json:"result,omitempty"`
	Summary *compositefingerprint.StackSummary    `json:"summary,omitempty"`
	Target  string                                `json:"target"`
	Error   string                                `json:"error,omitempty"`
}

func runWebFingerprintBatch(ctx context.Context, s *compositefingerprint.Scanner, opts webFingerprintOpts, options compositefingerprint.Options) error {
	targets, err := readWebScanList(opts.scanList)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("scan list %s is empty", opts.scanList)
	}
	concurrency := opts.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	// Pre-size the slice so workers can write to their assigned index
	// without locks — output order matches input order regardless of
	// completion order.
	records := make([]webBatchRecord, len(targets))
	indexes := make(chan int, len(targets))
	for i := range targets {
		indexes <- i
	}
	close(indexes)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indexes {
				if err := ctx.Err(); err != nil {
					records[i] = webBatchRecord{Target: targets[i], Error: err.Error()}
					continue
				}
				records[i] = scanOneTarget(ctx, s, targets[i], options, opts)
			}
		}()
	}
	wg.Wait()

	switch strings.ToLower(opts.output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if opts.summaryOnly {
			compact := make([]webBatchSummaryRecord, len(records))
			for i, r := range records {
				compact[i] = webBatchSummaryRecord{
					Target:  r.Target,
					Error:   r.Error,
					Summary: r.Summary,
				}
			}
			if err := enc.Encode(compact); err != nil {
				return fmt.Errorf("encode results: %w", err)
			}
		} else if err := enc.Encode(records); err != nil {
			return fmt.Errorf("encode results: %w", err)
		}
	case "ndjson":
		if err := writeWebFingerprintBatchNDJSON(records, opts.summaryOnly); err != nil {
			return err
		}
	case "csv":
		if err := writeWebFingerprintBatchCSV(records); err != nil {
			return err
		}
	case "text", "":
		writeWebFingerprintBatchText(records)
	default:
		return fmt.Errorf("unknown --output %q (want text, json, csv, or ndjson)", opts.output)
	}
	if len(opts.failOn) > 0 {
		for _, r := range records {
			if r.Result != nil && opts.failTriggered(*r.Result) {
				return failOnHitError{categories: opts.failOn}
			}
		}
	}
	return nil
}

// webBatchSummaryRecord is the lighter row emitted when --summary-only
// is set: the per-surface CompositeResult is dropped, keeping only the
// synthesised summary.
type webBatchSummaryRecord struct {
	Summary *compositefingerprint.StackSummary `json:"summary,omitempty"`
	Target  string                             `json:"target"`
	Error   string                             `json:"error,omitempty"`
}

// scanOneTarget runs one composite scan, applies any filters, and
// returns the per-target record. Pure function — safe for the worker-
// pool fan-out.
func scanOneTarget(ctx context.Context, s *compositefingerprint.Scanner, t string, options compositefingerprint.Options, opts webFingerprintOpts) webBatchRecord {
	scheme, host, port, err := splitWebTarget(t)
	if err != nil {
		return webBatchRecord{Target: t, Error: err.Error()}
	}
	raw, err := s.Scan(ctx, scheme, host, port, options)
	if err != nil {
		return webBatchRecord{Target: t, Error: err.Error()}
	}
	res := opts.applyFilters(raw)
	sum := res.Summarise()
	return webBatchRecord{Target: t, Result: &res, Summary: &sum}
}

// readWebScanList loads a newline-delimited target file. Blank lines
// and '#' comments are skipped so the file can be hand-edited safely.
// A path of "-" reads from stdin, matching the Unix convention used
// by curl/jq/sed/etc., so operators can pipe in a list:
//
//	cat urls.txt | kite-collector web-fingerprint --scan-list -
func readWebScanList(path string) ([]string, error) {
	var rc io.ReadCloser
	if path == "-" {
		rc = io.NopCloser(os.Stdin)
	} else {
		f, err := os.Open(path) //#nosec G304 -- CLI-supplied --scan-list path for web-fingerprint, intentional operator input
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		rc = f
	}
	defer func() { _ = rc.Close() }()
	var targets []string
	sc := bufio.NewScanner(rc)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return targets, nil
}

func writeWebFingerprintBatchText(records []webBatchRecord) {
	for _, r := range records {
		fmt.Printf("=== %s ===\n", r.Target)
		if r.Error != "" {
			fmt.Printf("  [error] %s\n", r.Error)
			continue
		}
		if r.Result == nil || r.Summary == nil {
			fmt.Println("  (no result)")
			continue
		}
		writeWebFingerprintText(*r.Result, *r.Summary)
		fmt.Println()
	}
}

// splitWebTarget parses a URL into (scheme, host, port). Defaults: 443
// for https, 80 for http.
func splitWebTarget(raw string) (string, string, int, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, fmt.Errorf("parse url %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", 0, fmt.Errorf("unsupported scheme %q (want http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", 0, fmt.Errorf("url %q has no host", raw)
	}
	port := 0
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid port %q: %w", p, err)
		}
	} else if scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	return scheme, host, port, nil
}

// writeWebFingerprintJSON emits a single JSON object with the full
// CompositeResult and the synthesised summary so a downstream tool can
// pick whichever view it needs. When summaryOnly is true the
// per-surface raw fingerprints are dropped and only the StackSummary
// is emitted — useful when downstream consumers only care about the
// synthesised view (smaller payload for batch jobs).
func writeWebFingerprintJSON(res compositefingerprint.CompositeResult, sum compositefingerprint.StackSummary, summaryOnly bool) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if summaryOnly {
		if err := enc.Encode(sum); err != nil {
			return fmt.Errorf("encode summary: %w", err)
		}
		return nil
	}
	doc := struct {
		Summary compositefingerprint.StackSummary    `json:"summary"`
		Result  compositefingerprint.CompositeResult `json:"result"`
	}{Summary: sum, Result: res}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode doc: %w", err)
	}
	return nil
}

// writeWebFingerprintNDJSON writes a single JSON line — for the
// single-URL path that's exactly one line, but the format is the
// streaming-friendly counterpart to writeWebFingerprintJSON: emitting
// one record per line lets a downstream pipe parse incrementally
// without buffering the whole array.
func writeWebFingerprintNDJSON(res compositefingerprint.CompositeResult, sum compositefingerprint.StackSummary, summaryOnly bool) error {
	enc := json.NewEncoder(os.Stdout)
	if summaryOnly {
		if err := enc.Encode(sum); err != nil {
			return fmt.Errorf("encode summary: %w", err)
		}
		return nil
	}
	if err := enc.Encode(struct {
		Summary compositefingerprint.StackSummary    `json:"summary"`
		Result  compositefingerprint.CompositeResult `json:"result"`
	}{Summary: sum, Result: res}); err != nil {
		return fmt.Errorf("encode doc: %w", err)
	}
	return nil
}

// writeWebFingerprintBatchNDJSON writes one JSON object per line for
// each per-target record. Operators can stream-process the output
// (`jq -c ... | xargs ...`) without waiting for the whole batch to
// finish serialising.
func writeWebFingerprintBatchNDJSON(records []webBatchRecord, summaryOnly bool) error {
	enc := json.NewEncoder(os.Stdout)
	for _, r := range records {
		if summaryOnly {
			row := webBatchSummaryRecord{
				Target:  r.Target,
				Error:   r.Error,
				Summary: r.Summary,
			}
			if err := enc.Encode(row); err != nil {
				return fmt.Errorf("encode row: %w", err)
			}
			continue
		}
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode record: %w", err)
		}
	}
	return nil
}

// writeWebFingerprintCSV writes one CSV row per non-nil StackSummary
// pick. Columns: target, layer, vendor, product, confidence, sources.
// One row per multi-pick slice entry (auth/analytics/data) so a
// single endpoint with three analytics SDKs produces three rows.
func writeWebFingerprintCSV(target string, sum compositefingerprint.StackSummary) error {
	w := csv.NewWriter(os.Stdout)
	if err := w.Write([]string{"target", "layer", "vendor", "product", "confidence", "sources"}); err != nil {
		return fmt.Errorf("csv write: %w", err)
	}
	if err := writeCSVRowsForSummary(w, target, sum); err != nil {
		return err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("csv flush: %w", err)
	}
	return nil
}

// writeWebFingerprintBatchCSV writes one CSV with one header row plus
// one row per pick per target. Per-target errors get their own row
// with layer="error" so they appear in the spreadsheet alongside the
// successful targets.
func writeWebFingerprintBatchCSV(records []webBatchRecord) error {
	w := csv.NewWriter(os.Stdout)
	if err := w.Write([]string{"target", "layer", "vendor", "product", "confidence", "sources"}); err != nil {
		return fmt.Errorf("csv write: %w", err)
	}
	for _, r := range records {
		if r.Error != "" {
			if err := w.Write([]string{r.Target, "error", "", r.Error, "", ""}); err != nil {
				return fmt.Errorf("csv write: %w", err)
			}
			continue
		}
		if r.Summary == nil {
			continue
		}
		if err := writeCSVRowsForSummary(w, r.Target, *r.Summary); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("csv flush: %w", err)
	}
	return nil
}

// writeCSVRowsForSummary emits one row per non-nil pick in sum. Used
// by both single-URL and batch CSV paths.
func writeCSVRowsForSummary(w *csv.Writer, target string, sum compositefingerprint.StackSummary) error {
	row := func(layer string, p *compositefingerprint.Pick) error {
		if p == nil {
			return nil
		}
		return w.Write([]string{
			target, layer, p.Vendor, p.Product, p.Confidence, strings.Join(p.Sources, ","),
		})
	}
	rows := func(layer string, ps []*compositefingerprint.Pick) error {
		for _, p := range ps {
			if err := row(layer, p); err != nil {
				return err
			}
		}
		return nil
	}
	for _, fn := range []func() error{
		func() error { return row("hosting", sum.Hosting) },
		func() error { return row("webserver", sum.WebServer) },
		func() error { return row("runtime", sum.Runtime) },
		func() error { return row("framework", sum.Framework) },
		func() error { return rows("auth", sum.Auth) },
		func() error { return rows("analytics", sum.Analytics) },
		func() error { return rows("data", sum.DataLayer) },
		func() error { return rows("secret-leak", sum.SecretsLeak) },
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// writeWebFingerprintText prints a human-readable per-layer summary.
// Layers with no pick are skipped so the output stays focused on what
// actually fired.
func writeWebFingerprintText(res compositefingerprint.CompositeResult, sum compositefingerprint.StackSummary) {
	fmt.Printf("endpoint: %s\n", sum.Endpoint)
	if res.Errors != nil {
		for _, e := range res.Errors {
			fmt.Printf("  [warn] %s: %s\n", e.Mechanism, e.Message)
		}
	}
	printPick := func(label string, p *compositefingerprint.Pick) {
		if p == nil {
			return
		}
		fmt.Printf("%-10s  %-12s  %s — %s  (%s)\n",
			label, p.Confidence, p.Vendor, p.Product, strings.Join(p.Sources, ","))
	}
	printPicks := func(label string, ps []*compositefingerprint.Pick) {
		for _, p := range ps {
			printPick(label, p)
		}
	}
	printPick("hosting", sum.Hosting)
	printPick("webserver", sum.WebServer)
	printPick("runtime", sum.Runtime)
	printPick("framework", sum.Framework)
	printPicks("auth", sum.Auth)
	printPicks("analytics", sum.Analytics)
	printPicks("data", sum.DataLayer)
	printPicks("secret-leak", sum.SecretsLeak)
	fmt.Printf("total raw fingerprints: %d\n", res.TotalFingerprints())
}
