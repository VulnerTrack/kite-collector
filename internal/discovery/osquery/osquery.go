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
			slog.Warn("osquery: yara rules matched on host",
				"code", string(LogCodeYaraMatchesFound), "count", len(matches))
		}
	}

	// FIM summary: recent file_events through the daemon's watch config. An
	// empty count with no file_paths configured is normal.
	if events, err := s.FileEvents(ctx, cfg, now.Add(-24*time.Hour).Unix()); err == nil {
		tags["file_events_24h"] = len(events)
	}

	tagsJSON, _ := json.Marshal(tags)
	machine.Tags = string(tagsJSON)

	slog.Info("osquery: discovery complete", "hostname", machine.Hostname) //#nosec G706 -- structured slog
	return []model.Machine{machine}, nil
}

// yaraScan runs the configured on-demand scans. Returns (matches, scanned):
// scanned is false when YARA was not configured or the sigfile could not be
// PROVEN visible to the daemon — the silent-zero contract means an unproven
// sigfile yields rows indistinguishable from "clean", so we refuse to report
// a clean result we cannot stand behind.
func (s *Source) yaraScan(ctx context.Context, client querier, cfg map[string]any) ([]YaraMatch, bool) {
	sigfile := toString(cfg["yara_sigfile"])
	paths := toStrings(cfg["yara_paths"])
	if sigfile == "" || len(paths) == 0 {
		return nil, false
	}

	// Prove the sigfile exists in the DAEMON's mount namespace (which may not
	// be ours). osquery's `file` table errors without a path constraint, so
	// this is a constrained probe, and a zero-row answer means the daemon
	// cannot see the rules file.
	vis, err := client.Query(ctx, fmt.Sprintf("SELECT path FROM file WHERE path = '%s';", sqlEscape(sigfile)))
	if err != nil || len(vis) == 0 {
		slog.Warn("osquery: yara sigfile not visible to daemon; scan skipped",
			"code", string(LogCodeYaraSigfileInvisible), "sigfile", sigfile, "error", err)
		return nil, false
	}

	var matches []YaraMatch
	for _, p := range paths {
		rows, err := client.Query(ctx, fmt.Sprintf(
			"SELECT path, matches, count FROM yara WHERE path = '%s' AND sigfile = '%s';",
			sqlEscape(p), sqlEscape(sigfile)))
		if err != nil {
			slog.Warn("osquery: yara scan failed",
				"code", string(LogCodeYaraScanFailed), "path", p, "error", err)
			continue
		}
		for _, r := range rows {
			if n := atoi(r["count"]); n > 0 {
				matches = append(matches, YaraMatch{Path: r["path"], Matches: r["matches"], Count: n})
			}
		}
	}
	return matches, true
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
	client := s.newClient(socket)
	rows, err := client.Query(ctx, fmt.Sprintf(
		"SELECT target_path, category, action, sha256, time FROM file_events WHERE time > %d;", sinceUnix))
	if err != nil {
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
