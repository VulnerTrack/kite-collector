package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	processEnvSecretsAuditorName = "process_env_secrets" //#nosec G101 -- auditor identifier, not a credential

	// CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
	processEnvSecretsCWEID   = "CWE-526"
	processEnvSecretsCWEName = "Cleartext Storage of Sensitive Information in an Environment Variable" //#nosec G101 -- CWE description text, not a credential

	processEnvSecretsExpected   = "No credentials in process environment variables"
	processEnvSecretsCISControl = "CIS 3.11, CIS 14.8" //#nosec G101 -- CIS control reference, not a credential

	// defaultMaxPIDsScanned caps the number of PIDs scanned per Audit
	// invocation to bound execution time on busy hosts.
	defaultMaxPIDsScanned = 10_000

	// maxEnvBlockSize bounds the bytes read from each /proc/<pid>/environ
	// to defend against pathological process env sizes. Linux's typical
	// ARG_MAX is 128 KiB; we double that to be safe.
	maxEnvBlockSize = 256 * 1024
)

// ProcessEnvSecrets scans Linux host process environment blocks
// (`/proc/<pid>/environ`) for hard-coded credentials matching the shared
// secretPatterns ruleset. It implements Auditor; it is a no-op for any
// asset whose AssetType is not AssetTypeServer (the agent host) and on
// non-Linux platforms.
//
// The agent's own PID and kernel threads are always skipped (R6).
type ProcessEnvSecrets struct {
	procRoot     string
	processes    []string // optional case-insensitive filter; empty = all
	denyPrefixes []string
	maxPIDs      int
	selfPID      int
}

// ProcessEnvSecretsConfig configures a ProcessEnvSecrets auditor.
type ProcessEnvSecretsConfig struct {
	// ProcRoot is the path to /proc. Tests can override; defaults to /proc.
	ProcRoot string
	// Processes is an optional case-insensitive name filter. When empty
	// every process readable by the agent is scanned.
	Processes []string
	// ExtraDenyPrefixes is appended to the built-in default deny list.
	ExtraDenyPrefixes []string
	// MaxPIDs caps the number of PIDs scanned per Audit. <=0 uses the
	// default of 10,000.
	MaxPIDs int
}

// NewProcessEnvSecrets constructs a ProcessEnvSecrets auditor with the
// given configuration.
func NewProcessEnvSecrets(cfg ProcessEnvSecretsConfig) *ProcessEnvSecrets {
	procRoot := cfg.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	deny := make([]string, 0, len(defaultEnvDenyPrefixes)+len(cfg.ExtraDenyPrefixes))
	deny = append(deny, defaultEnvDenyPrefixes...)
	for _, e := range cfg.ExtraDenyPrefixes {
		if e == "" {
			continue
		}
		deny = append(deny, e)
	}
	max := cfg.MaxPIDs
	if max <= 0 {
		max = defaultMaxPIDsScanned
	}
	return &ProcessEnvSecrets{
		procRoot:     procRoot,
		processes:    cfg.Processes,
		denyPrefixes: deny,
		maxPIDs:      max,
		selfPID:      os.Getpid(),
	}
}

// Name returns the auditor identifier.
func (p *ProcessEnvSecrets) Name() string { return processEnvSecretsAuditorName }

// Audit walks /proc, reads each readable /proc/<pid>/environ, and applies
// secretPatterns to every env var value. The agent's own process and
// kernel threads (empty /proc/<pid>/comm) are skipped. Returns nil
// findings on non-Linux platforms or for non-server assets.
func (p *ProcessEnvSecrets) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.AssetType != model.AssetTypeServer {
		return nil, nil
	}
	if runtime.GOOS != "linux" {
		slog.Debug("process_env_secrets: non-linux platform, scan skipped",
			"goos", runtime.GOOS)
		return nil, nil
	}

	entries, err := os.ReadDir(p.procRoot)
	if err != nil {
		// /proc not readable — degrade gracefully.
		slog.Warn("process_env_secrets: read proc failed", "proc", p.procRoot, "error", err)
		return nil, nil
	}

	now := time.Now().UTC()
	var (
		findings []model.ConfigFinding
		scanned  int
	)

	filterSet := buildFilterSet(p.processes)

	for _, e := range entries {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		if !e.IsDir() {
			continue
		}
		pid, ok := pidFromName(e.Name())
		if !ok {
			continue
		}
		if pid == p.selfPID {
			continue
		}
		if scanned >= p.maxPIDs {
			slog.Warn("process_env_secrets: reached max pids cap; remainder skipped",
				"max", p.maxPIDs)
			break
		}
		scanned++

		comm := readProcText(filepath.Join(p.procRoot, e.Name(), "comm"))
		if comm == "" {
			// Kernel threads have an empty comm; skip them.
			continue
		}
		if filterSet != nil && !filterSet[strings.ToLower(comm)] {
			continue
		}

		envPath := filepath.Join(p.procRoot, e.Name(), "environ")
		envBytes, readErr := readProcCapped(envPath, maxEnvBlockSize)
		if readErr != nil {
			// Per-PID permission denied or vanished process — DEBUG and
			// move on. We never want a single unreadable PID to fail the
			// whole scan.
			if !errors.Is(readErr, fs.ErrPermission) && !errors.Is(readErr, fs.ErrNotExist) {
				slog.Debug("process_env_secrets: read environ failed",
					"pid", pid, "error", readErr)
			}
			continue
		}

		findings = append(findings,
			scanProcessEnv(asset, pid, comm, envBytes, p.denyPrefixes, now)...)
	}

	if len(findings) > 0 {
		slog.Info("process_env_secrets: findings detected",
			"asset_id", asset.ID,
			"count", len(findings),
			"scanned", scanned,
		)
	}

	return findings, nil
}

// scanProcessEnv applies the secretPatterns to every NUL-separated
// KEY=VALUE entry in envBytes and returns one ConfigFinding per
// (pattern, env_var_name) pair, deduplicated within this PID.
func scanProcessEnv(
	asset model.Asset,
	pid int,
	processName string,
	envBytes []byte,
	denyPrefixes []string,
	now time.Time,
) []model.ConfigFinding {
	if len(envBytes) == 0 {
		return nil
	}

	var findings []model.ConfigFinding
	seen := make(map[string]bool)

	for _, entry := range bytes.Split(envBytes, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		kv := string(entry)
		name, value, ok := splitEnvKV(kv)
		if !ok || value == "" {
			continue
		}
		if matchesAnyPrefix(name, denyPrefixes) {
			continue
		}

		for _, pat := range secretPatterns {
			if !pat.Re.MatchString(value) {
				continue
			}

			dedupeKey := pat.ID + ":" + name + ":" + strconv.Itoa(pid)
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			valueHash := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))[:16]
			// Note: pid is intentionally excluded from the deterministic
			// finding ID — pids are ephemeral. Identity is asset+pattern
			// +name+process_name so a process restart preserves
			// first_seen_at across scans.
			seed := fmt.Sprintf("process_env_secrets:%s:%s:%s:%s",
				asset.ID, pat.ID, processName, name)
			findingID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed))

			evidence := fmt.Sprintf("ENV[%s]=<redacted> detected in process:%s (PID %d) hash:%s",
				name, processName, pid, valueHash)

			findings = append(findings, model.ConfigFinding{
				ID:          findingID,
				AssetID:     asset.ID,
				Auditor:     processEnvSecretsAuditorName,
				CheckID:     pat.ID,
				Title:       fmt.Sprintf("Process env secret: %s", pat.Name),
				Severity:    pat.Severity,
				CWEID:       processEnvSecretsCWEID,
				CWEName:     processEnvSecretsCWEName,
				Evidence:    evidence,
				Expected:    processEnvSecretsExpected,
				Remediation: pat.Remediation,
				CISControl:  processEnvSecretsCISControl,
				Timestamp:   now,
			})
		}
	}

	return findings
}

// buildFilterSet returns a lowercase set of process names from filter, or
// nil when the filter is empty (meaning: scan every process).
func buildFilterSet(filter []string) map[string]bool {
	if len(filter) == 0 {
		return nil
	}
	set := make(map[string]bool, len(filter))
	for _, name := range filter {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		set[strings.ToLower(name)] = true
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// pidFromName parses a /proc directory entry name as a numeric PID. Non-
// numeric names (e.g. "self", "thread-self", "sys") return ok=false.
func pidFromName(name string) (int, bool) {
	for _, c := range name {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// readProcText reads a small /proc text file and returns its contents
// trimmed of trailing whitespace. Errors yield an empty string.
func readProcText(path string) string {
	data, err := readProcCapped(path, 4096)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readProcCapped opens path and reads at most max bytes. Returns the read
// bytes and any error from the open/read syscalls. EOF is not treated as
// an error.
func readProcCapped(path string, max int) ([]byte, error) {
	f, err := os.Open(path) //#nosec G304 -- /proc paths are agent-internal
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, int64(max)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// Compile-time interface check.
var _ Auditor = (*ProcessEnvSecrets)(nil)
