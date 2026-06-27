package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/discovery/cloud/storage"
)

// newStorageFingerprintCmd builds the `kite-collector storage-fingerprint`
// subcommand. The command exposes the storage detector to analysts who want
// to inspect a single URL or a local JS file without running a full scan
// cycle. It is intentionally read-only and side-effect free: the detector
// makes one HTTP GET when --url is set, parses a local file when --file is
// set, and prints the result.
func newStorageFingerprintCmd() *cobra.Command {
	var (
		target    string
		page      string
		file      string
		scanList  string
		providers []string
		minConf   int
		signals   []string
		output    string
		timeout   time.Duration
		maxBody   int
		userAgent string
	)

	cmd := &cobra.Command{
		Use:   "storage-fingerprint",
		Short: "Detect S3-compatible storage providers from a URL or JS file",
		Long: `Analyse a target URL or a local JavaScript bundle for evidence of
S3-compatible object-storage providers (AWS S3, Supabase Storage, GCS, Azure
Blob, Backblaze B2, Cloudflare R2, DigitalOcean Spaces, MinIO, Wasabi,
Tigris, Linode, Scaleway).

The detector evaluates file (SDK), TLS, JA4/JA4S/JA4H, JA5, API, network,
and bucket signals. With --url the command performs one HTTP GET and feeds
the response into the detector. With --file no network traffic is generated;
the file contents are treated as the JS evidence.`,
		Example: `  # Probe a CDN-hosted JS bundle and print matches as a table
  kite-collector storage-fingerprint --url https://cdn.example.com/app.js

  # Analyse a downloaded bundle locally, in JSON
  kite-collector storage-fingerprint --file ./app.min.js --output json

  # Only show high-confidence Supabase or R2 matches
  kite-collector storage-fingerprint --url https://example.com \
      --providers supabase_storage,cloudflare_r2 --min-confidence 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStorageFingerprint(storageFingerprintOpts{
				target:    target,
				page:      page,
				file:      file,
				scanList:  scanList,
				providers: providers,
				minConf:   minConf,
				signals:   signals,
				output:    output,
				timeout:   timeout,
				maxBody:   maxBody,
				userAgent: userAgent,
			})
		},
	}

	cmd.Flags().StringVar(&target, "url", "", "remote URL to probe (mutually exclusive with --file/--page/--scan-list)")
	cmd.Flags().StringVar(&page, "page", "", "HTML page URL to crawl; analyses every <script src=...>")
	cmd.Flags().StringVar(&file, "file", "", "local JS file to analyse (mutually exclusive with --url/--page/--scan-list)")
	cmd.Flags().StringVar(&scanList, "scan-list", "", "newline-delimited file of URLs to probe (# comments allowed)")
	cmd.Flags().StringSliceVar(&providers, "providers", nil, "filter to these providers (comma-separated)")
	cmd.Flags().IntVar(&minConf, "min-confidence", 0, "minimum confidence band: 1=low, 2=medium, 3=high")
	cmd.Flags().StringSliceVar(&signals, "signals", nil, "restrict to these signal types (file,tls,ja4,ja4s,ja4h,ja5,api,network,bucket)")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table, json")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP probe timeout")
	cmd.Flags().IntVar(&maxBody, "max-body", 5*1024*1024, "maximum response body bytes to read")
	cmd.Flags().StringVar(&userAgent, "user-agent", "kite-collector/storage-fingerprint", "User-Agent header for the probe")

	return cmd
}

type storageFingerprintOpts struct {
	target    string
	page      string
	file      string
	scanList  string
	output    string
	userAgent string
	providers []string
	signals   []string
	timeout   time.Duration
	maxBody   int
	minConf   int
}

func runStorageFingerprint(opts storageFingerprintOpts) error {
	modes := 0
	if opts.target != "" {
		modes++
	}
	if opts.page != "" {
		modes++
	}
	if opts.file != "" {
		modes++
	}
	if opts.scanList != "" {
		modes++
	}
	switch modes {
	case 0:
		return errors.New("must specify exactly one of --url, --page, --file, or --scan-list")
	case 1:
	default:
		return errors.New("--url, --page, --file, and --scan-list are mutually exclusive")
	}
	if opts.minConf < 0 || opts.minConf > 3 {
		return fmt.Errorf("--min-confidence must be between 0 and 3, got %d", opts.minConf)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	filter := buildStorageFilter(opts)

	if opts.scanList != "" {
		return runStorageFingerprintBatch(ctx, opts, filter)
	}
	if opts.page != "" {
		return runStorageFingerprintPage(ctx, opts, filter)
	}

	var (
		result storage.AnalyzeResult
		err    error
	)

	if opts.target != "" {
		a := storage.NewAnalyzer(storage.AnalyzerOptions{
			MaxBodyBytes: int64(opts.maxBody),
			Timeout:      opts.timeout,
			UserAgent:    opts.userAgent,
		})
		result, err = a.Analyze(ctx, opts.target)
		if err != nil {
			return fmt.Errorf("probe %s: %w", opts.target, err)
		}
	} else {
		data, readErr := os.ReadFile(opts.file)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", opts.file, readErr)
		}
		ev := storage.Evidence{Filename: opts.file, JS: string(data)}
		result = storage.AnalyzeResult{Evidence: ev, Matches: storage.Detect(ev)}
	}

	filtered := filter.Apply(result.Matches)

	switch strings.ToLower(opts.output) {
	case "json":
		return writeStorageJSON(result.Evidence, filtered)
	case "table", "":
		writeStorageTable(opts, result.Evidence, filtered)
		return nil
	default:
		return fmt.Errorf("unknown --output %q (want table or json)", opts.output)
	}
}

// batchResult bundles a single target's outcome for the --scan-list path.
// Errors are kept per-target so a failure in one URL does not abort the rest.
type batchResult struct {
	Target  string          `json:"target"`
	Error   string          `json:"error,omitempty"`
	Matches []storage.Match `json:"matches,omitempty"`
}

// runStorageFingerprintBatch reads targets from opts.scanList, probes each
// one sequentially, and emits an aggregated report. Sequential I/O keeps the
// implementation simple and avoids surprising the operator with bursty
// concurrent probes; a follow-up could parallelise behind a flag.
func runStorageFingerprintBatch(ctx context.Context, opts storageFingerprintOpts, filter storage.Filter) error {
	targets, err := readScanList(opts.scanList)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("scan list %s is empty", opts.scanList)
	}

	a := storage.NewAnalyzer(storage.AnalyzerOptions{
		MaxBodyBytes: int64(opts.maxBody),
		Timeout:      opts.timeout,
		UserAgent:    opts.userAgent,
	})

	results := make([]batchResult, 0, len(targets))
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			results = append(results, batchResult{Target: t, Error: err.Error()})
			break
		}
		res, err := a.Analyze(ctx, t)
		if err != nil {
			results = append(results, batchResult{Target: t, Error: err.Error()})
			continue
		}
		results = append(results, batchResult{Target: t, Matches: filter.Apply(res.Matches)})
	}

	switch strings.ToLower(opts.output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("encode results: %w", err)
		}
		return nil
	case "table", "":
		writeStorageBatchTable(results)
		return nil
	default:
		return fmt.Errorf("unknown --output %q (want table or json)", opts.output)
	}
}

// readScanList loads a newline-delimited target file. Blank lines and lines
// that start with '#' (after leading whitespace) are skipped so the file
// can be commented for operator review.
func readScanList(path string) ([]string, error) {
	f, err := os.Open(path) //#nosec G304 -- CLI-supplied --scan-list path for storage-fingerprint, intentional operator input
	if err != nil {
		return nil, fmt.Errorf("open scan list %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read scan list %s: %w", path, err)
	}
	return out, nil
}

// writeStorageBatchTable prints a compact one-row-per-target summary plus
// per-row provider/signal breakdown for matched targets.
func writeStorageBatchTable(results []batchResult) {
	fmt.Println()
	fmt.Println("Storage Fingerprint — Batch Scan")
	fmt.Println("================================")
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  TARGET\tSTATUS\tMATCHES\tPROVIDERS")
	matched, errored := 0, 0
	for _, r := range results {
		status := "ok"
		providers := "—"
		switch {
		case r.Error != "":
			status = "error"
			providers = r.Error
			errored++
		case len(r.Matches) == 0:
			status = "clean"
		default:
			matched++
			providers = strings.Join(uniqueProviders(r.Matches), ",")
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%d\t%s\n",
			truncateSnippet(r.Target, 60), status, len(r.Matches), truncateSnippet(providers, 60))
	}
	_ = w.Flush()
	fmt.Printf("\n  %d target(s); %d with matches, %d error(s).\n", len(results), matched, errored)
}

// uniqueProviders returns the sorted set of providers seen in matches.
func uniqueProviders(matches []storage.Match) []string {
	seen := map[string]struct{}{}
	for _, m := range matches {
		seen[string(m.Provider)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sortStrings(out)
	return out
}

// sortStrings keeps the import surface small — sort.Strings would work too,
// but the helper avoids an extra package import in this single use site.
func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1] > in[j]; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}

// runStorageFingerprintPage crawls an HTML page, extracts every <script src>
// reference, and analyses each one. The page output reuses batch rendering
// so analysts get a per-script summary identical to the --scan-list mode.
func runStorageFingerprintPage(ctx context.Context, opts storageFingerprintOpts, filter storage.Filter) error {
	a := storage.NewAnalyzer(storage.AnalyzerOptions{
		MaxBodyBytes: int64(opts.maxBody),
		Timeout:      opts.timeout,
		UserAgent:    opts.userAgent,
	})
	pageResults, err := a.AnalyzePage(ctx, opts.page)
	if err != nil {
		return fmt.Errorf("crawl %s: %w", opts.page, err)
	}

	results := make([]batchResult, 0, len(pageResults))
	for _, pr := range pageResults {
		br := batchResult{Target: pr.Target}
		if pr.Err != nil {
			br.Error = pr.Err.Error()
		} else {
			br.Matches = filter.Apply(pr.Result.Matches)
		}
		results = append(results, br)
	}

	switch strings.ToLower(opts.output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("encode results: %w", err)
		}
		return nil
	case "table", "":
		fmt.Printf("\nStorage Fingerprint — Page Crawl\n================================\n")
		fmt.Printf("  Page: %s\n", opts.page)
		writeStorageBatchTable(results)
		return nil
	default:
		return fmt.Errorf("unknown --output %q (want table or json)", opts.output)
	}
}

// buildStorageFilter translates CLI flags into a storage.Filter. Empty
// flag values yield an unrestricted filter — Apply already treats nil
// slices as "no constraint".
func buildStorageFilter(opts storageFingerprintOpts) storage.Filter {
	f := storage.Filter{MinConfidence: storage.Confidence(opts.minConf)} //#nosec G115 -- opts.minConf bounded to 0..3 by validation above
	for _, p := range opts.providers {
		if p == "" {
			continue
		}
		f.Providers = append(f.Providers, storage.Provider(strings.TrimSpace(p)))
	}
	for _, s := range opts.signals {
		if s == "" {
			continue
		}
		f.Signals = append(f.Signals, storage.SignalType(strings.TrimSpace(s)))
	}
	return f
}

// writeStorageJSON emits a stable JSON object so downstream tooling can
// parse the result. The Evidence is included (minus the JS body, which
// would dwarf everything else) so a reader can audit what the detector saw.
func writeStorageJSON(ev storage.Evidence, matches []storage.Match) error {
	type evidenceSummary struct {
		URL           string   `json:"url,omitempty"`
		Filename      string   `json:"filename,omitempty"`
		BucketHost    string   `json:"bucket_host,omitempty"`
		TLSServerName string   `json:"tls_server_name,omitempty"`
		TLSSANs       []string `json:"tls_sans,omitempty"`
		HeaderCount   int      `json:"header_count,omitempty"`
		JSBytes       int      `json:"js_bytes,omitempty"`
	}
	payload := struct {
		Matches  []storage.Match `json:"matches"`
		Evidence evidenceSummary `json:"evidence"`
	}{
		Evidence: evidenceSummary{
			URL:           ev.URL,
			Filename:      ev.Filename,
			BucketHost:    ev.BucketHost,
			TLSServerName: ev.TLSServerName,
			TLSSANs:       ev.TLSSANs,
			HeaderCount:   len(ev.APIHeaders),
			JSBytes:       len(ev.JS),
		},
		Matches: matches,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	return nil
}

// writeStorageTable renders a human-friendly summary: source, evidence
// metadata, then one row per match with provider/signal/confidence/snippet.
func writeStorageTable(opts storageFingerprintOpts, ev storage.Evidence, matches []storage.Match) {
	source := opts.target
	if source == "" {
		source = opts.file
	}

	fmt.Println()
	fmt.Println("Storage Fingerprint")
	fmt.Println("===================")
	fmt.Printf("  Source       : %s\n", source)
	if ev.BucketHost != "" {
		fmt.Printf("  Bucket host  : %s\n", ev.BucketHost)
	}
	if ev.TLSServerName != "" {
		fmt.Printf("  TLS SNI/CN   : %s\n", ev.TLSServerName)
	}
	if len(ev.TLSSANs) > 0 {
		fmt.Printf("  TLS SANs     : %s\n", strings.Join(ev.TLSSANs, ", "))
	}
	if len(ev.APIHeaders) > 0 {
		fmt.Printf("  Headers      : %d response headers observed\n", len(ev.APIHeaders))
	}
	if len(ev.JS) > 0 {
		fmt.Printf("  JS body      : %d bytes\n", len(ev.JS))
	}
	fmt.Println()

	if len(matches) == 0 {
		fmt.Println("  No matches.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  PROVIDER\tSIGNAL\tCONFIDENCE\tREASON\tSNIPPET")
	for _, m := range matches {
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
			m.Provider, m.Signal, confidenceLabel(m.Confidence), m.Reason, truncateSnippet(m.Snippet, 60))
	}
	_ = w.Flush()
	fmt.Printf("\n  Total: %d match(es).\n", len(matches))
}

// confidenceLabel maps the numeric confidence band to a short word for the
// table renderer. The numeric value is kept in the JSON output.
func confidenceLabel(c storage.Confidence) string {
	switch c {
	case storage.ConfidenceHigh:
		return "high"
	case storage.ConfidenceMedium:
		return "medium"
	case storage.ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}

// truncateSnippet bounds the displayed snippet width in the table so a long
// regex hit doesn't push every column off the right edge of the terminal.
func truncateSnippet(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
