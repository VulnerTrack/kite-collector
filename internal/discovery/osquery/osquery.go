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

	sys, err := client.Query(ctx, "SELECT hostname, uuid, hardware_vendor, hardware_model, cpu_type, physical_memory FROM system_info;")
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

	// Optional on-demand YARA sweep.
	if matches, scanned := s.yaraScan(ctx, client, cfg); scanned {
		tags["yara_scanned"] = true
		tags["yara_match_count"] = len(matches)
		if len(matches) > 0 {
			tags["yara_matches"] = matches
			// Rule names are operator-authored (never file contents), so
			// naming them here is alert-safe and saves the on-call a pivot
			// into the machine record.
			slog.Warn("osquery: yara rules matched on host",
				"code", string(LogCodeYaraMatchesFound),
				"count", len(matches),
				"rules", matchedRuleNames(matches))
		}
	}

	// FIM summary: recent file_events through the daemon's watch config. An
	// empty count with no file_paths configured is normal — but a FAILED
	// query is not an empty count, so it must not be silent: without the
	// warning, "0 events" and "events subsystem broken" are indistinguishable
	// to an operator.
	if events, err := fileEventsWith(ctx, client, now.Add(-24*time.Hour).Unix()); err == nil {
		tags["file_events_24h"] = len(events)
	} else {
		slog.Warn("osquery: file_events summary failed",
			"code", string(LogCodeDiscoverFileEventsFailed), "error", err)
	}

	tagsJSON, _ := json.Marshal(tags)
	machine.Tags = string(tagsJSON)

	slog.Info("osquery: discovery complete", "hostname", machine.Hostname) //#nosec G706 -- structured slog
	return []model.Machine{machine}, nil
}

// yaraScan runs the configured on-demand scans. Returns (matches, scanned):
// scanned is false when YARA was not configured or the rule credential could
// not be PROVEN usable by the daemon — the silent-zero contract means an
// unproven credential yields rows indistinguishable from "clean", so we
// refuse to report a clean result we cannot stand behind.
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
func (s *Source) yaraScan(ctx context.Context, client querier, cfg map[string]any) ([]YaraMatch, bool) {
	paths := toStrings(cfg["yara_paths"])
	if len(paths) == 0 {
		return nil, false
	}

	sigfile := toString(cfg["yara_sigfile"])
	rules := joinRules(cfg["yara_rules"])

	switch {
	case rules != "":
		return s.yaraScanWith(ctx, client, paths, "sigrule", rules, s.proveRulesCompile)
	case sigfile != "":
		return s.yaraScanWith(ctx, client, paths, "sigfile", sigfile, s.proveSigfileVisible)
	default:
		return nil, false
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
) ([]YaraMatch, bool) {
	if !prove(ctx, client, value) {
		return nil, false
	}

	var (
		matches []YaraMatch
		scanned int // paths the daemon actually scanned without error
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
		scanned++
		for _, r := range rows {
			if n := atoi(r["count"]); n > 0 {
				matches = append(matches, YaraMatch{Path: r["path"], Matches: r["matches"], Count: n})
			}
		}
	}

	// The credential proof only established that the RULES are usable — the
	// sigfile visibility probe never exercises the `yara` table itself. If
	// every path then errored (yara table absent, e.g. a FreeBSD daemon; or
	// all paths unreadable), no scan actually ran, so reporting a clean
	// 0-match result would be a false clean — the exact failure this
	// integration exists to prevent. Refuse it.
	if scanned == 0 {
		slog.Warn("osquery: every yara scan path errored; scan not reported",
			"code", string(LogCodeYaraAllPathsFailed), "paths", len(paths))
		return nil, false
	}
	return matches, true
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

// fileEventsWith is FileEvents against an already-connected client, so
// Discover reuses its session instead of re-resolving and re-dialing.
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
		Hostname:        sys["hostname"],
		MachineType:     machineType,
		OSFamily:        osFamily,
		OSVersion:       osVersion,
		KernelVersion:   kern["version"],
		Architecture:    osv["arch"],
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
