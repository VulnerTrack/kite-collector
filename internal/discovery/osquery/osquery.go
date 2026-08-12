// Package osquery implements a discovery.Source that reads the local host's
// identity — and optionally YARA scan results and file-integrity events —
// from a running osqueryd over its Thrift extensions socket. Communication
// is a minimal hand-rolled binary-protocol client (thrift.go); no vendor SDK,
// mirroring the docker source.
//
// The source registers unconditionally but no-ops with an error (logged as a
// per-scan warning by the registry) unless an osqueryd socket is resolvable:
// cfg["socket"] → KITE_OSQUERY_SOCKET → platform default paths. Nothing runs
// against osquery on hosts that don't have it.
//
// Error contract (pinned by tests/e2e/osquery/edge.sh): the daemon rejects
// bad SQL / unknown tables / unconstrained virtual tables LOUDLY
// (queryError), but a missing or uncompilable YARA sigfile and a missing
// scan target are SILENT — rc 0, zero rows. Zero rows is therefore never
// read as "scanned clean" without first proving the sigfile is visible to
// the daemon (see yaraScan).
package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Source implements discovery.Source against a local osqueryd.
type Source struct {
	// newClient is swappable for tests.
	newClient func(socket string) querier
}

// querier is the client surface Discover consumes.
type querier interface {
	Query(ctx context.Context, sql string) ([]map[string]string, error)
	Ping(ctx context.Context) error
}

// New returns a new osquery discovery source.
func New() *Source {
	return &Source{newClient: func(s string) querier { return NewClient(s) }}
}

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "osquery" }

// YaraMatch is one YARA rule hit reported by the daemon's on-demand scanner.
type YaraMatch struct {
	Path    string `json:"path"`
	Matches string `json:"matches"`
	Count   int64  `json:"count"`
}

// FileEvent is one FIM record from osquery's file_events table.
type FileEvent struct {
	TargetPath string `json:"target_path"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	SHA256     string `json:"sha256,omitempty"`
	Time       int64  `json:"time"`
}

// Discover reads host identity from osquery and returns one Machine. The
// socket resolves from (in order): cfg["socket"], KITE_OSQUERY_SOCKET, then
// platform default paths.
//
// Supported config keys:
//
//	socket        – string; extensions socket path (unix socket / \\.\pipe\...)
//	yara_sigfile  – string; rules file path AS SEEN BY THE DAEMON
//	yara_rules    – []string or string; inline YARA rule text (no daemon-side
//	                file needed; takes precedence over yara_sigfile)
//	yara_paths    – []string; file paths for the daemon to scan on demand
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Machine, error) {
	socket := resolveSocket(cfg)
	if socket == "" {
		return nil, fmt.Errorf("osquery: no extensions socket found; set KITE_OSQUERY_SOCKET or sources.osquery.socket, or install osqueryd")
	}

	client := s.newClient(socket)

	info, err := client.Query(ctx, "SELECT version, build_platform, pid FROM osquery_info;")
	if err != nil {
		return nil, fmt.Errorf("osquery: osquery_info: %w", err)
	}
	if len(info) == 0 {
		return nil, fmt.Errorf("osquery: daemon answered but returned no osquery_info row")
	}

	slog.Info("osquery: connected", "socket", socket, "version", info[0]["version"]) //#nosec G706 -- structured slog

	sys, err := client.Query(ctx, "SELECT hostname, computer_name, uuid, hardware_vendor, hardware_model, cpu_type, physical_memory FROM system_info;")
	if err != nil {
		slog.Warn("osquery: system_info failed", "code", string(LogCodeDiscoverSystemInfoFailed), "error", err)
	}
	osv, err := client.Query(ctx, "SELECT name, version, platform, platform_like, arch FROM os_version;")
	if err != nil {
		slog.Warn("osquery: os_version failed", "code", string(LogCodeDiscoverOSVersionFailed), "error", err)
	}
	kern, err := client.Query(ctx, "SELECT version FROM kernel_info;")
	if err != nil {
		slog.Warn("osquery: kernel_info failed", "code", string(LogCodeDiscoverKernelInfoFailed), "error", err)
	}

	now := time.Now().UTC()
	machine := buildMachine(first(info), first(sys), first(osv), first(kern), now)

	tags := map[string]any{
		"osquery_version": first(info)["version"],
		"build_platform":  first(info)["build_platform"],
	}
	if v := first(sys)["uuid"]; v != "" {
		tags["hardware_uuid"] = v
	}
	if v := first(sys)["hardware_vendor"]; v != "" {
		tags["hardware_vendor"] = v
	}
	if v := first(sys)["hardware_model"]; v != "" {
		tags["hardware_model"] = v
	}
	// cpu_type and physical_memory were already fetched by the system_info
	// query but previously discarded — surface them; they are core inventory
	// facts (processor and installed RAM). physical_memory is BIGINT bytes.
	if v := first(sys)["cpu_type"]; v != "" {
		tags["cpu_type"] = v
	}
	if v := first(sys)["physical_memory"]; v != "" {
		if bytes := atoi(v); bytes > 0 {
			tags["physical_memory_bytes"] = bytes
		}
	}
	// system_info.hostname is the FQDN (getFqdn: gethostname + a DNS
	// AI_CANONNAME lookup). The Machine.Hostname used for dedup comes from
	// computer_name (= gethostname) to match the agent probe's os.Hostname,
	// so keep the FQDN here as a reference attribute when it actually differs.
	if fqdn := first(sys)["hostname"]; fqdn != "" && fqdn != machine.Hostname {
		tags["fqdn"] = fqdn
	}

	// Optional on-demand YARA sweep.
	if res := s.yaraScan(ctx, client, cfg); res.scanned {
		tags["yara_scanned"] = true
		tags["yara_match_count"] = len(res.matches)
		// A non-zero unscannable count means some configured paths produced no
		// scan (missing/unreadable/directory/empty glob). Surface it so a
		// "0 matches" result is not mistaken for full coverage.
		if res.unscannable > 0 {
			tags["yara_paths_unscannable"] = res.unscannable
		}
		if len(res.matches) > 0 {
			tags["yara_matches"] = res.matches
			// Rule names are operator-authored (never file contents), so
			// naming them here is alert-safe and saves the on-call a pivot
			// into the machine record.
			slog.Warn("osquery: yara rules matched on host",
				"code", string(LogCodeYaraMatchesFound),
				"count", len(res.matches),
				"rules", matchedRuleNames(res.matches))
		}
	}

	// FIM summary: file_events the daemon still retains. The window is the
	// daemon's own events_expiry (default 3600s), NOT a fixed 24h: osquery
	// purges evented rows older than events_expiry (eventsubscriberplugin.cpp
	// expireEventBatches), so a longer window can never return more — naming
	// the count "24h" would overstate coverage, since hundreds of events may
	// have already expired. The window is tagged alongside the count so the
	// number is self-describing. An empty count with no file_paths configured
	// is normal; a FAILED query is not — without the warning, "0 events" and
	// "events subsystem broken" are indistinguishable to an operator.
	windowSecs := eventsExpiryWindow(ctx, client)
	since := now.Add(-time.Duration(windowSecs) * time.Second).Unix()
	if events, err := fileEventsWith(ctx, client, since); err == nil {
		tags["file_events_recent"] = len(events)
		tags["file_events_window_secs"] = windowSecs
	} else {
		slog.Warn("osquery: file_events summary failed",
			"code", string(LogCodeDiscoverFileEventsFailed), "error", err)
	}

	tagsJSON, _ := json.Marshal(tags)
	machine.Tags = string(tagsJSON)

	slog.Info("osquery: discovery complete", "hostname", machine.Hostname) //#nosec G706 -- structured slog
	return []model.Machine{machine}, nil
}

// yaraScanResult is what a sweep reports back to Discover. scanned is false
// when YARA was not configured or the credential could not be PROVEN usable —
// the silent-zero contract means an unproven credential yields rows
// indistinguishable from "clean", so we refuse to report a result we cannot
// stand behind. unscannable counts configured paths the daemon opened nothing
// for (missing/unreadable/directory/empty glob) — real coverage gaps that a
// "0 matches" number would otherwise hide.
type yaraScanResult struct {
	matches     []YaraMatch
	scanned     bool
	unscannable int
}

// yaraScan runs the configured on-demand scans.
//
// Two credential forms, chosen by config (yara_rules wins if both are set,
// since inline rules need no daemon-side file):
//
//	yara_sigfile – a rules file path the daemon reads. Fragile: the daemon's
//	               mount namespace may differ from ours, so we prove the file
//	               is visible via the `file` table before trusting a scan.
//	yara_rules   – inline YARA rule text sent in the query itself (sigrule).
//	               No file dependency, so no visibility problem — but a
//	               malformed rule is silently dropped (0 rows, same shape as
//	               "no match"), so we prove it COMPILES via a probe scan
//	               against the daemon's own binary before trusting a scan.
func (s *Source) yaraScan(ctx context.Context, client querier, cfg map[string]any) yaraScanResult {
	paths := toStrings(cfg["yara_paths"])
	if len(paths) == 0 {
		return yaraScanResult{}
	}

	sigfile := toString(cfg["yara_sigfile"])
	rules := joinRules(cfg["yara_rules"])

	switch {
	case rules != "":
		return s.yaraScanWith(ctx, client, paths, "sigrule", rules, s.proveRulesCompile)
	case sigfile != "":
		return s.yaraScanWith(ctx, client, paths, "sigfile", sigfile, s.proveSigfileVisible)
	default:
		return yaraScanResult{}
	}
}

// credentialProof establishes that a scan credential (a sigfile path or an
// inline rule set) is actually usable by the daemon. Returns false to skip
// the scan rather than report a clean result that a silent zero-row answer
// cannot back.
type credentialProof func(ctx context.Context, client querier, value string) bool

// yaraScanWith runs the path loop for one credential form after its proof
// passes. constraint is the WHERE column osquery keys on ("sigfile" or
// "sigrule").
func (s *Source) yaraScanWith(
	ctx context.Context,
	client querier,
	paths []string,
	constraint, value string,
	prove credentialProof,
) yaraScanResult {
	if !prove(ctx, client, value) {
		return yaraScanResult{}
	}

	var (
		matches     []YaraMatch
		scanned     int // paths the daemon actually opened and scanned
		unscannable int // paths that produced no scan (missing/dir/unreadable/empty glob)
	)
	for _, p := range paths {
		rows, err := client.Query(ctx, fmt.Sprintf(
			"SELECT path, matches, count FROM yara WHERE path = '%s' AND %s = '%s';",
			sqlEscape(p), constraint, sqlEscape(value)))
		if err != nil {
			slog.Warn("osquery: yara scan failed",
				"code", string(LogCodeYaraScanFailed), "path", p, "error", err)
			continue
		}
		// osquery's doYARAScanPath pushes a row ONLY when it opened and
		// scanned a file (ERROR_SUCCESS) — a scanned-clean file still yields
		// one row with count 0. Zero rows therefore means the daemon scanned
		// NOTHING for this path (missing, a directory, unreadable, or a glob
		// that matched no readable file), which is NOT the same as "clean".
		// Counting it as scanned would be a per-path false clean.
		if len(rows) == 0 {
			unscannable++
			slog.Warn("osquery: yara scan target produced no scan; path skipped",
				"code", string(LogCodeYaraPathUnscannable), "path", p)
			continue
		}
		scanned++
		for _, r := range rows {
			if n := atoi(r["count"]); n > 0 {
				matches = append(matches, YaraMatch{Path: r["path"], Matches: r["matches"], Count: n})
			}
		}
	}

	// The credential proof only established that the RULES are usable — the
	// sigfile visibility probe never exercises the `yara` table itself, and a
	// per-path scan can silently open nothing. If NO path was actually
	// scanned (yara table absent, e.g. a FreeBSD daemon; every path errored;
	// or every target was unscannable), reporting a clean 0-match result
	// would be a false clean — the exact failure this integration exists to
	// prevent. Refuse it.
	if scanned == 0 {
		slog.Warn("osquery: no yara scan path was actually scanned; scan not reported",
			"code", string(LogCodeYaraAllPathsFailed), "paths", len(paths), "unscannable", unscannable)
		return yaraScanResult{}
	}
	return yaraScanResult{matches: matches, scanned: true, unscannable: unscannable}
}

// proveSigfileVisible confirms the daemon can see the sigfile. osquery's
// `file` table errors without a path constraint, so this is a constrained
// probe. The two ways it can refuse are DIFFERENT failure modes with
// different remediations, so they get distinct codes: a probe error means
// the daemon/table is broken (fix the daemon); zero rows means the daemon
// genuinely cannot see the rules file (fix the sigfile path or its mount).
func (s *Source) proveSigfileVisible(ctx context.Context, client querier, sigfile string) bool {
	vis, err := client.Query(ctx, fmt.Sprintf("SELECT path FROM file WHERE path = '%s';", sqlEscape(sigfile)))
	if err != nil {
		slog.Warn("osquery: yara sigfile visibility probe failed; scan skipped",
			"code", string(LogCodeYaraSigfileProbeFailed), "sigfile", sigfile, "error", err)
		return false
	}
	if len(vis) == 0 {
		slog.Warn("osquery: yara sigfile not visible to daemon; scan skipped",
			"code", string(LogCodeYaraSigfileInvisible), "sigfile", sigfile)
		return false
	}
	return true
}

// proveRulesCompile confirms inline rules compile before trusting a scan.
// osquery drops a malformed rule silently (0 rows, indistinguishable from
// "no match"), so we scan the rules against the daemon's OWN binary — a path
// guaranteed to exist and be readable in the daemon's namespace: a compiled
// rule yields exactly one row there (count 0), a broken rule yields none.
func (s *Source) proveRulesCompile(ctx context.Context, client querier, rules string) bool {
	self, err := client.Query(ctx, "SELECT p.path AS path FROM processes p, osquery_info i WHERE p.pid = i.pid;")
	if err != nil || len(self) == 0 || self[0]["path"] == "" {
		slog.Warn("osquery: could not resolve daemon binary for yara compile probe; scan skipped",
			"code", string(LogCodeYaraCompileProbeFailed), "error", err)
		return false
	}
	probe, err := client.Query(ctx, fmt.Sprintf(
		"SELECT count FROM yara WHERE path = '%s' AND sigrule = '%s';",
		sqlEscape(self[0]["path"]), sqlEscape(rules)))
	if err != nil {
		slog.Warn("osquery: yara rule compile probe failed; scan skipped",
			"code", string(LogCodeYaraCompileProbeFailed), "error", err)
		return false
	}
	if len(probe) == 0 {
		slog.Warn("osquery: inline yara rules did not compile; scan skipped",
			"code", string(LogCodeYaraRulesUncompilable))
		return false
	}
	return true
}

// FileEvents returns FIM records newer than sinceUnix from the daemon's
// file_events table. The daemon only has events for path categories in its
// own file_paths config — and per the inotify watch-descriptor collision
// pinned by the sim, paths also watched by yara_events never appear here.
func (s *Source) FileEvents(ctx context.Context, cfg map[string]any, sinceUnix int64) ([]FileEvent, error) {
	socket := resolveSocket(cfg)
	if socket == "" {
		return nil, fmt.Errorf("osquery: no extensions socket found")
	}
	return fileEventsWith(ctx, s.newClient(socket), sinceUnix)
}

// eventsExpiryWindow returns the daemon's events_expiry (seconds), the true
// retention horizon for evented tables. Falls back to osquery's 3600s default
// when the flag can't be read, so the caller always has a sane window.
func eventsExpiryWindow(ctx context.Context, client querier) int64 {
	const defaultExpiry = 3600
	rows, err := client.Query(ctx, "SELECT value FROM osquery_flags WHERE name = 'events_expiry';")
	if err != nil || len(rows) == 0 {
		return defaultExpiry
	}
	if v := atoi(rows[0]["value"]); v > 0 {
		return v
	}
	return defaultExpiry
}

// fileEventsWith is FileEvents against an already-connected client, so
// Discover reuses its session instead of re-resolving and re-dialing.
//
// The `WHERE time > N` constraint is load-bearing beyond filtering: osquery's
// events framework runs a differential "optimize" mode
// (shouldOptimize = isDaemon() && events_optimize, both defaults on) that
// returns only events since the query last ran — but ONLY when the query
// carries no `time` constraint (genTable sets can_optimize=false as soon as a
// time predicate is present). Keeping the constraint pins snapshot semantics,
// so repeated scans see a consistent window instead of a shrinking
// differential. Do not drop it.
//
// file_events is POSIX-only in osquery's table specs; a Windows daemon (the
// MSI's kite-osqueryd) serves the NTFS USN journal as ntfs_journal_events
// instead. An unknown-table rejection therefore falls back to the NTFS shape
// mapped onto the same FileEvent struct — platform-correct without a
// platform probe, and only ever an extra round-trip on Windows daemons.
// Action strings pass through in the daemon's own vocabulary (CREATED /
// UPDATED on POSIX, Write / Delete / rename pairs on Windows).
func fileEventsWith(ctx context.Context, client querier, sinceUnix int64) ([]FileEvent, error) {
	rows, err := client.Query(ctx, fmt.Sprintf(
		"SELECT target_path, category, action, sha256, time FROM file_events WHERE time > %d;", sinceUnix))
	if err != nil {
		if IsQueryError(err) && strings.Contains(err.Error(), "no such table") {
			return ntfsJournalEventsWith(ctx, client, sinceUnix)
		}
		return nil, fmt.Errorf("osquery: file_events: %w", err)
	}
	events := make([]FileEvent, 0, len(rows))
	for _, r := range rows {
		events = append(events, FileEvent{
			TargetPath: r["target_path"],
			Category:   r["category"],
			Action:     r["action"],
			SHA256:     r["sha256"],
			Time:       atoi(r["time"]),
		})
	}
	return events, nil
}

// ntfsJournalEventsWith reads Windows FIM records. ntfs_journal_events has no
// sha256 column and names the changed file `path`, not `target_path`
// (specs/windows/ntfs_journal_events.table).
func ntfsJournalEventsWith(ctx context.Context, client querier, sinceUnix int64) ([]FileEvent, error) {
	rows, err := client.Query(ctx, fmt.Sprintf(
		"SELECT path, category, action, time FROM ntfs_journal_events WHERE time > %d;", sinceUnix))
	if err != nil {
		return nil, fmt.Errorf("osquery: ntfs_journal_events: %w", err)
	}
	events := make([]FileEvent, 0, len(rows))
	for _, r := range rows {
		events = append(events, FileEvent{
			TargetPath: r["path"],
			Category:   r["category"],
			Action:     r["action"],
			Time:       atoi(r["time"]),
		})
	}
	return events, nil
}

// matchedRuleNames flattens the distinct rule names across matches for the
// alert log line, preserving first-seen order.
func matchedRuleNames(matches []YaraMatch) []string {
	seen := make(map[string]bool)
	var names []string
	for _, m := range matches {
		for _, rule := range strings.Split(m.Matches, ",") {
			rule = strings.TrimSpace(rule)
			if rule != "" && !seen[rule] {
				seen[rule] = true
				names = append(names, rule)
			}
		}
	}
	return names
}

// normalizeArch maps an osquery arch string to the GOARCH vocabulary the
// agent probe uses (runtime.GOARCH: amd64, arm64, 386, arm). A host with
// osquery installed is discovered by BOTH this source and the local agent
// probe; both produce a Machine with the same NaturalKey, so they must agree
// on Architecture or the two records churn the MaterialFingerprint (which
// includes Architecture) on every scan.
//
// osquery's arch is a uname machine string on Linux/macOS (x86_64, aarch64,
// armv7l, ...) and a WMI OSArchitecture string on Windows ("64-bit",
// "32-bit", "ARM 64-bit Processor"). Unknown values pass through lowercased
// so nothing is discarded — only the families that diverge are reconciled.
// The Windows "64-bit" → amd64 mapping is best-effort (it can't tell amd64
// from a 64-bit non-ARM edge case), but ARM is disambiguated first.
func normalizeArch(raw string) string {
	a := strings.ToLower(strings.TrimSpace(raw))
	switch a {
	case "x86_64", "amd64", "x64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i486", "i586", "i686", "x86":
		return "386"
	case "armv6l", "armv7l", "armv8l", "arm":
		return "arm"
	case "":
		return ""
	}
	// Windows WMI OSArchitecture phrases ("64-bit", "32-bit", "ARM 64-bit
	// Processor"). Gate on "bit" so real GOARCH names that merely contain a
	// width digit — ppc64le, riscv64, s390x, mips64 — pass through untouched
	// instead of being swept into amd64. ARM is checked first so "ARM 64-bit"
	// does not fall into amd64.
	if strings.Contains(a, "bit") {
		switch {
		case strings.Contains(a, "arm") && strings.Contains(a, "32"):
			return "arm"
		case strings.Contains(a, "arm"):
			return "arm64"
		case strings.Contains(a, "64"):
			return "amd64"
		case strings.Contains(a, "32"):
			return "386"
		}
	}
	return a
}

// hostname picks the Machine.Hostname used for dedup. osquery's
// system_info.hostname is the FQDN (getFqdn = gethostname + a DNS
// AI_CANONNAME lookup), which on a domain-joined host differs from the short
// name the agent probe reports via os.Hostname (= gethostname). Since the
// central deduper keys NaturalKey on raw Hostname, an FQDN here would split
// the same host into two records. computer_name is exactly gethostname, so
// prefer it; fall back to the FQDN only when computer_name is absent (older
// daemons / partial rows) so we never end up with an empty hostname.
func hostname(sys map[string]string) string {
	if cn := sys["computer_name"]; cn != "" {
		return cn
	}
	return sys["hostname"]
}

// buildMachine maps osquery identity rows onto the Machine model.
func buildMachine(info, sys, osv, kern map[string]string, now time.Time) model.Machine {
	// osquery reports the distro slug (ubuntu, rhel, arch...) as platform on
	// Linux; only windows/darwin come through literally.
	osFamily := ""
	switch platform := osv["platform"]; platform {
	case "windows", "darwin":
		osFamily = platform
	case "":
		osFamily = ""
	default:
		osFamily = "linux"
	}

	osVersion := strings.TrimSpace(osv["name"] + " " + osv["version"])

	machineType := model.MachineTypeServer
	if osFamily == "windows" || osFamily == "darwin" {
		machineType = model.MachineTypeWorkstation
	}

	return model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname(sys),
		MachineType:     machineType,
		OSFamily:        osFamily,
		OSVersion:       osVersion,
		KernelVersion:   kern["version"],
		Architecture:    normalizeArch(osv["arch"]),
		DiscoverySource: "osquery",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
}

// resolveSocket applies the cfg → env → auto-detect precedence.
func resolveSocket(cfg map[string]any) string {
	if s := toString(cfg["socket"]); s != "" {
		return s
	}
	if s := os.Getenv("KITE_OSQUERY_SOCKET"); s != "" {
		return s
	}
	return detectSocket()
}

// sqlEscape doubles single quotes for embedding a value in a SQL string
// literal. osquery's extension API has no parameter binding; paths here come
// from the operator's own config, so this guards syntax, not trust.
func sqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func first(rows []map[string]string) map[string]string {
	if len(rows) == 0 {
		return map[string]string{}
	}
	return rows[0]
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// joinRules coalesces the yara_rules config value into a single rule text
// block. Accepts a bare string (one rule) or a list of rule strings (joined
// with newlines, as YARA concatenates rules), so operators can express rules
// either way in config.
func joinRules(v any) string {
	if s := toString(v); s != "" {
		return s
	}
	if list := toStrings(v); len(list) > 0 {
		return strings.Join(list, "\n")
	}
	return ""
}

// toStrings accepts []string or []any-of-string (what YAML/JSON config
// decoding produces).
func toStrings(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ensure Source satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Machine, error)
} = (*Source)(nil)
