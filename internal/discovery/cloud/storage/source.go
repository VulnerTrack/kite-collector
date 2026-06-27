package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Source implements discovery.Source by probing a configured list of asset
// URLs (typically JS bundles served from a webapp) and turning each
// detected S3-compatible bucket into a model.Asset.
//
// Configuration map (set via the kite-collector.yaml `storage_fingerprint`
// block):
//
//	targets             []string  Direct JS URLs to probe (HTTPS recommended).
//	page_targets        []string  HTML pages to crawl; every <script src=...>
//	                              found on the page is added to the probe queue.
//	providers_allowlist []string  Optional. When non-empty, only these
//	                              providers are surfaced as assets.
//	min_confidence      int       0..3. Defaults to 0 (no minimum).
//	timeout             string    Go duration ("10s"). Default 10s.
//	max_body_bytes      int       Per-probe body cap. Default 5 MiB.
//	user_agent          string    Optional probe User-Agent.
//	signature_file      string    Optional path to a JSON/YAML file of
//	                              additional signatures appended to the
//	                              built-in catalogue.
//
// Probes are sequential — the engine already runs sources in parallel, so
// adding intra-source concurrency would just stack up sockets without
// changing wall-clock for the average user.
type Source struct {
	analyzer *Analyzer
	now      func() time.Time
}

// NewSource builds a Source with the default Analyzer. The Discover loop
// rebuilds the analyzer when timeout / max_body_bytes / user_agent are set
// via configuration, so the default here is only a fallback.
func NewSource() *Source {
	return &Source{
		analyzer: NewAnalyzer(AnalyzerOptions{}),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier used by the discovery registry and the
// kite-collector configuration block.
func (s *Source) Name() string { return "storage_fingerprint" }

// Discover probes every configured target, applies the filter, and emits
// one cloud_instance asset per unique bucket host. Per-probe failures are
// logged and skipped — partial results from successful probes are still
// returned, matching the graceful-degradation contract of cloud/aws.go.
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	targets := stringSliceFromCfg(cfg["targets"])
	pageTargets := stringSliceFromCfg(cfg["page_targets"])
	if len(targets) == 0 && len(pageTargets) == 0 {
		slog.Info("storage_fingerprint: no targets configured; skipping",
			"source", s.Name())
		return nil, nil
	}

	opts := AnalyzerOptions{
		UserAgent: stringFromCfg(cfg["user_agent"]),
	}
	if mb := intFromCfg(cfg["max_body_bytes"]); mb > 0 {
		opts.MaxBodyBytes = int64(mb)
	}
	if to := durationFromCfg(cfg["timeout"]); to > 0 {
		opts.Timeout = to
	}
	analyzer := NewAnalyzer(opts)

	// Build the effective signature catalogue. When signature_file is set
	// we merge file-loaded signatures onto the built-in list; a parse
	// error degrades to the built-in catalogue so a malformed file does
	// not silently disable discovery.
	sigs := catalogue
	if path := stringFromCfg(cfg["signature_file"]); path != "" {
		extra, err := LoadSignaturesFromFile(path)
		if err != nil {
			slog.Warn("storage_fingerprint signature_file load failed; using built-in catalogue only",
				"source", s.Name(),
				"path", path,
				"error", err)
		} else {
			sigs = MergedCatalogue(extra)
			slog.Info("storage_fingerprint loaded external signatures",
				"source", s.Name(),
				"path", path,
				"count", len(extra))
		}
	}
	analyzer.signatures = sigs

	filter := Filter{MinConfidence: Confidence(intFromCfg(cfg["min_confidence"]))}
	for _, p := range stringSliceFromCfg(cfg["providers_allowlist"]) {
		filter.Providers = append(filter.Providers, Provider(p))
	}

	var assets []model.Asset
	seen := make(map[string]struct{})

	// addMatches converts one analysed evidence/match pair into an asset
	// (when the bucket host is novel) and appends it to the result slice.
	// Pulled out so the direct-target and page-crawl loops share dedup.
	addMatches := func(target string, res AnalyzeResult) {
		matches := filter.Apply(res.Matches)
		if len(matches) == 0 {
			return
		}
		host := res.Evidence.BucketHost
		if host == "" {
			slog.Info("storage_fingerprint match without bucket host",
				"source", s.Name(),
				"target", target,
				"matches", len(matches))
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		assets = append(assets, s.buildAsset(host, matches))
	}

	// Crawl page_targets first. Each <script src=...> on a page becomes a
	// probe; the analyser handles per-script fan-out and we just iterate
	// its results.
	for _, page := range pageTargets {
		if err := ctx.Err(); err != nil {
			return assets, fmt.Errorf("storage_fingerprint cancelled: %w", err)
		}
		pageResults, err := analyzer.AnalyzePage(ctx, page)
		if err != nil {
			slog.Warn("storage_fingerprint page crawl failed",
				"source", s.Name(),
				"page", page,
				"error", err)
			continue
		}
		for _, pr := range pageResults {
			if pr.Err != nil {
				slog.Warn("storage_fingerprint script probe failed",
					"source", s.Name(),
					"page", page,
					"target", pr.Target,
					"error", pr.Err)
				continue
			}
			addMatches(pr.Target, pr.Result)
		}
	}

	// Then direct targets. Skipping seen hosts keeps the output stable
	// when an operator configures both a page and a direct JS URL pointing
	// at the same bucket.
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return assets, fmt.Errorf("storage_fingerprint cancelled: %w", err)
		}
		res, err := analyzer.Analyze(ctx, target)
		if err != nil {
			slog.Warn("storage_fingerprint probe failed",
				"source", s.Name(),
				"target", target,
				"error", err)
			continue
		}
		addMatches(target, res)
	}

	slog.Info("storage_fingerprint discovery complete",
		"source", s.Name(),
		"targets", len(targets),
		"page_targets", len(pageTargets),
		"assets", len(assets))
	return assets, nil
}

// buildAsset turns a bucket host plus its match set into a model.Asset.
// The primary provider is whichever match has the highest confidence;
// ties are broken by signal-type stability (sorted alphabetically) so the
// dedup natural key stays stable across scans.
func (s *Source) buildAsset(host string, matches []Match) model.Asset {
	primary := pickPrimary(matches)
	tags := summariseMatches(matches, primary)

	now := s.now()
	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		AssetType:       model.AssetTypeCloudInstance,
		Hostname:        host,
		DiscoverySource: s.Name(),
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Environment:     string(primary.Provider),
		Tags:            tags,
	}
	asset.ComputeNaturalKey()
	return asset
}

// pickPrimary returns the highest-confidence match, breaking ties by
// signal type sorted ascending so the choice is deterministic.
func pickPrimary(matches []Match) Match {
	sorted := append([]Match(nil), matches...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Confidence != sorted[j].Confidence {
			return sorted[i].Confidence > sorted[j].Confidence
		}
		return sorted[i].Signal < sorted[j].Signal
	})
	return sorted[0]
}

// summariseMatches serialises a compact summary into the asset's Tags field.
// The schema is JSON so downstream consumers (dashboard, reconciler) can
// parse it without bespoke logic. Marshal cannot fail for these flat types;
// we ignore the error to keep the function infallible.
func summariseMatches(matches []Match, primary Match) string {
	signals := make(map[string]int)
	providers := make(map[string]int)
	for _, m := range matches {
		signals[string(m.Signal)]++
		providers[string(m.Provider)]++
	}

	payload := struct {
		PrimaryProvider string         `json:"primary_provider"`
		Signals         map[string]int `json:"signals"`
		Providers       map[string]int `json:"providers"`
		MatchCount      int            `json:"match_count"`
		PrimaryConfidence Confidence   `json:"primary_confidence"`
	}{
		PrimaryProvider:   string(primary.Provider),
		Signals:           signals,
		Providers:         providers,
		MatchCount:        len(matches),
		PrimaryConfidence: primary.Confidence,
	}
	out, _ := json.Marshal(payload)
	return string(out)
}

// stringSliceFromCfg extracts a []string from a YAML-decoded config value.
// Accepts []string and []any (the common YAML decoding shape).
func stringSliceFromCfg(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// stringFromCfg extracts a string from a YAML-decoded value.
func stringFromCfg(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// intFromCfg accepts int, int64, and float64 (YAML decodes integer
// literals as either int or float64 depending on the library).
func intFromCfg(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// durationFromCfg accepts a Go-format duration string ("10s", "1m") or a
// raw number of seconds.
func durationFromCfg(v any) time.Duration {
	switch n := v.(type) {
	case string:
		if d, err := time.ParseDuration(n); err == nil {
			return d
		}
	case int:
		return time.Duration(n) * time.Second
	case int64:
		return time.Duration(n) * time.Second
	case float64:
		return time.Duration(n) * time.Second
	}
	return 0
}
