package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	scaAuditorName = "sca"

	// CWE-1395: Dependency on Vulnerable Third-Party Component
	scaCWEID   = "CWE-1395"
	scaCWEName = "Dependency on Vulnerable Third-Party Component"
)

// SCA is a Software Composition Analysis auditor. It reads dependency
// manifests (go.mod, package.json, requirements.txt, Cargo.toml) from a
// repository asset, queries the OSV vulnerability database, and returns one
// ConfigFinding per confirmed vulnerability.
//
// The auditor is a no-op for non-repository assets, so it is safe to register
// it in the same audit.Registry as SSH/kernel/firewall auditors.
type SCA struct {
	osv     *osvClient
	timeout time.Duration
}

// NewSCA creates an SCA auditor. timeout controls the OSV API request timeout;
// pass 0 to use the default of 30 seconds.
func NewSCA(timeout time.Duration) *SCA {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &SCA{
		osv:     newOSVClient(timeout),
		timeout: timeout,
	}
}

// Name returns the auditor identifier.
func (s *SCA) Name() string { return scaAuditorName }

// Audit runs SCA on the given asset. It returns nil findings for any asset
// that is not of type AssetTypeRepository.
func (s *SCA) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.AssetType != model.AssetTypeRepository {
		return nil, nil
	}

	repoPath := extractRepoPath(asset.Tags)
	if repoPath == "" {
		slog.Warn("sca: repository asset has no path tag, skipping", "asset_id", asset.ID)
		return nil, nil
	}

	deps, parseErrs := CollectDependencies(repoPath)
	for _, e := range parseErrs {
		slog.Warn("sca: manifest parse error", "asset_id", asset.ID, "error", e)
	}

	if len(deps) == 0 {
		slog.Debug("sca: no dependencies found", "path", repoPath)
		return nil, nil
	}

	slog.Info("sca: querying OSV", "asset_id", asset.ID, "deps", len(deps), "path", repoPath)

	// Use a child context so the OSV call respects any outer deadline.
	queryCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	results, err := s.osv.QueryBatch(queryCtx, deps)
	if err != nil {
		// Treat network failures as warnings; return partial empty results
		// so the scan continues rather than failing entirely.
		slog.Warn("sca: OSV query failed", "asset_id", asset.ID, "error", err)
		return nil, nil
	}

	now := time.Now().UTC()
	var findings []model.ConfigFinding

	for i, dep := range deps {
		if i >= len(results) {
			break
		}
		for _, vuln := range results[i] {
			f := buildSCAFinding(asset, dep, vuln, now)
			findings = append(findings, f)
		}
	}

	if len(findings) > 0 {
		slog.Info("sca: vulnerabilities found",
			"asset_id", asset.ID,
			"path", repoPath,
			"count", len(findings),
		)
	}

	return findings, nil
}

// buildSCAFinding constructs a ConfigFinding for a single (dependency, vuln) pair.
// The finding ID is deterministic so that first_seen_at is preserved across scans.
func buildSCAFinding(asset model.Asset, dep Dependency, vuln osvVuln, now time.Time) model.ConfigFinding {
	cveID := firstCVE(vuln)
	fixed := fixedVersion(vuln)
	severity := osvVulnSeverity(vuln)

	// Deterministic ID: same vuln on the same asset always maps to the same UUID,
	// which preserves first_seen_at when the finding reappears in a later scan.
	seed := fmt.Sprintf("sca:%s:%s:%s", asset.ID, dep.Name, cveID)
	findingID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed))

	checkID := fmt.Sprintf("sca-%s-%s",
		strings.ToLower(dep.Ecosystem),
		sanitizeCheckID(dep.Name),
	)

	evidence := fmt.Sprintf("%s@%s (%s) — %s", dep.Name, dep.Version, dep.Ecosystem, cveID)

	expected := dep.Version
	remediation := fmt.Sprintf("Upgrade %s to a patched version", dep.Name)
	if fixed != "" {
		expected = fmt.Sprintf(">= %s", fixed)
		remediation = fmt.Sprintf("Upgrade %s to %s or later", dep.Name, fixed)
	}

	return model.ConfigFinding{
		ID:          findingID,
		AssetID:     asset.ID,
		Auditor:     scaAuditorName,
		CheckID:     checkID,
		Title:       fmt.Sprintf("Vulnerable dependency: %s (%s)", dep.Name, cveID),
		Severity:    severity,
		CWEID:       scaCWEID,
		CWEName:     scaCWEName,
		Evidence:    evidence,
		Expected:    expected,
		Remediation: remediation,
		Timestamp:   now,
	}
}

// sanitizeCheckID replaces characters not suitable for a check ID slug.
func sanitizeCheckID(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// extractRepoPath reads the "path" key from an asset's JSON tags field.
func extractRepoPath(tags string) string {
	if tags == "" {
		return ""
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(tags), &m); err != nil {
		return ""
	}
	return m["path"]
}

// Compile-time interface check.
var _ Auditor = (*SCA)(nil)
