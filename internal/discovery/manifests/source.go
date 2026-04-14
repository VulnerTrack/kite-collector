package manifests

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/discovery/manifests/parsers"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Compile-time interface check.
var _ discovery.Source = (*Source)(nil)

// Source implements discovery.Source for manifest and git-repository scanning.
type Source struct {
	registry  *parsers.Registry
	software  map[uuid.UUID][]model.InstalledSoftware
	findings  []model.ConfigFinding
	scanRoots []string // resolved scan root paths for path validation
	mu        sync.Mutex
}

// NewSource creates a manifest discovery source with all known parsers.
func NewSource() *Source {
	return &Source{
		registry: parsers.NewRegistry(),
	}
}

func (s *Source) Name() string { return "manifests" }

// Discover walks the filesystem, parses dependency manifests, and returns
// discovered project and repository assets.  Discovered software and
// findings are stored internally and accessible via CollectedSoftware and
// CollectedFindings.
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	sc := parseSourceConfig(cfg)

	s.mu.Lock()
	s.software = make(map[uuid.UUID][]model.InstalledSoftware)
	s.findings = nil
	s.scanRoots = resolveRoots(sc.scanPaths)
	s.mu.Unlock()

	// Build walker config from parser registry.
	wcfg := WalkerConfig{
		ScanPaths:        sc.scanPaths,
		MaxDepth:         sc.maxDepth,
		MaxFileSizeBytes: int64(sc.maxFileSizeMB) * 1024 * 1024,
		ExcludeDirs:      sc.excludeDirs,
		Filenames:        s.registry.Filenames(),
		GlobPatterns:     s.registry.GlobPatterns(),
		DetectGit:        sc.gitEnabled,
	}

	// Phase 1: collect all matches.
	var matches []WalkMatch
	if err := Walk(ctx, wcfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("manifest walk: %w", err)
	}

	slog.Info("manifest scanner: walk complete",
		"matches", len(matches))

	// Phase 2: apply lockfile preference — if a lockfile exists in a directory,
	// skip the corresponding manifest.
	if sc.preferLockfiles {
		matches = applyLockfilePreference(matches)
	}

	// Phase 3: parse manifests, evaluate policies, and build assets.
	var assets []model.Asset
	now := time.Now().UTC()
	policy := sc.policyEngine

	for _, m := range matches {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		if m.IsGitDir {
			asset := s.processGitRepo(ctx, m.Path, now, sc)
			if asset != nil {
				assets = append(assets, *asset)
			}
			continue
		}

		asset, sw, deps := s.parseManifest(ctx, m.Path, now)
		if asset == nil {
			continue
		}
		assets = append(assets, *asset)

		if len(sw) > 0 {
			s.mu.Lock()
			s.software[asset.ID] = sw
			s.mu.Unlock()
		}

		// Evaluate dependency policies.
		if policy != nil {
			for _, dep := range deps {
				pf := policy.Evaluate(dep, asset.ID, now)
				if len(pf) > 0 {
					s.mu.Lock()
					s.findings = append(s.findings, pf...)
					s.mu.Unlock()
				}
			}
		}
	}

	slog.Info("manifest scanner: discovery complete",
		"assets", len(assets),
		"total_software", s.totalSoftware())

	return assets, nil
}

// CollectedSoftware returns software discovered during the last Discover call,
// keyed by asset ID.
func (s *Source) CollectedSoftware() map[uuid.UUID][]model.InstalledSoftware {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.software
}

// CollectedFindings returns policy findings from the last Discover call.
func (s *Source) CollectedFindings() []model.ConfigFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findings
}

func (s *Source) parseManifest(ctx context.Context, path string, now time.Time) (*model.Asset, []model.InstalledSoftware, []parsers.Dependency) {
	base := filepath.Base(path)
	parser := s.registry.Match(base)
	if parser == nil {
		return nil, nil, nil
	}

	// Validate path is within configured scan roots (defence against path traversal).
	if !isWithinRoots(path, s.scanRoots) {
		slog.Warn("manifest scanner: path outside scan roots", "path", path)
		return nil, nil, nil
	}

	content, err := os.ReadFile(path) // #nosec G304 -- path validated above
	if err != nil {
		slog.Warn("manifest scanner: read error",
			"path", path, "error", err)
		return nil, nil, nil
	}

	result, err := parser.Parse(ctx, path, content)
	if err != nil {
		slog.Warn("manifest scanner: parse error",
			"path", path, "error", err)
		return nil, nil, nil
	}

	for _, e := range result.Errors {
		slog.Debug("manifest scanner: parse warning",
			"path", path, "warning", e)
	}

	// Create asset for this manifest.
	assetID := newID()
	hostname := result.ProjectName
	if hostname == "" {
		hostname = filepath.Base(filepath.Dir(path))
	}

	asset := model.Asset{
		ID:              assetID,
		AssetType:       model.AssetTypeSoftwareProject,
		Hostname:        hostname,
		DiscoverySource: "manifest_scanner",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            manifestTags(path, parser.Ecosystem(), result),
	}
	asset.ComputeNaturalKey()

	// Convert dependencies to InstalledSoftware.
	var sw []model.InstalledSoftware
	for _, dep := range result.Dependencies {
		sw = append(sw, model.InstalledSoftware{
			ID:             newID(),
			AssetID:        assetID,
			SoftwareName:   dep.Name,
			Vendor:         dep.Vendor,
			Version:        dep.Version,
			PackageManager: parser.Ecosystem(),
			CPE23:          software.BuildCPE23WithTargetSW(dep.Vendor, dep.Name, dep.Version, parser.Ecosystem()),
		})
	}

	return &asset, sw, result.Dependencies
}

func (s *Source) processGitRepo(ctx context.Context, gitDirPath string, now time.Time, sc sourceConfig) *model.Asset {
	info, err := DetectGitRepo(ctx, gitDirPath, sc.gitDetectDirty, sc.gitStaleDays)
	if err != nil {
		slog.Warn("manifest scanner: git detection error",
			"path", gitDirPath, "error", err)
		return nil
	}

	hostname := info.RemoteURL
	if hostname == "" {
		hostname = filepath.Base(info.Path)
	}

	tags := map[string]any{
		"local_path":  info.Path,
		"branch":      info.Branch,
		"head_commit": info.HeadCommit,
		"remote_url":  info.RemoteURL,
		"repo_name":   info.RepoName,
		"is_dirty":    info.IsDirty,
		"is_stale":    info.IsStale,
	}
	if !info.LastCommitDate.IsZero() {
		tags["last_commit_date"] = info.LastCommitDate.Format(time.RFC3339)
	}
	tagsJSON, _ := json.Marshal(tags)

	asset := model.Asset{
		ID:              newID(),
		AssetType:       model.AssetTypeRepository,
		Hostname:        hostname,
		DiscoverySource: "manifest_scanner",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
	}
	asset.ComputeNaturalKey()

	// Generate findings for stale/dirty repos.
	if info.IsStale {
		finding := model.ConfigFinding{
			ID:          newID(),
			AssetID:     asset.ID,
			Timestamp:   now,
			Auditor:     "manifest_scanner",
			CheckID:     "git:stale_repo",
			Title:       fmt.Sprintf("Stale repository: %s (no commits in %d days)", info.RepoName, sc.gitStaleDays),
			Severity:    model.SeverityMedium,
			Evidence:    fmt.Sprintf("Last commit: %s", info.LastCommitDate.Format(time.RFC3339)),
			Remediation: "Review repository for relevance; update or archive.",
		}
		s.mu.Lock()
		s.findings = append(s.findings, finding)
		s.mu.Unlock()
	}
	if info.IsDirty {
		finding := model.ConfigFinding{
			ID:          newID(),
			AssetID:     asset.ID,
			Timestamp:   now,
			Auditor:     "manifest_scanner",
			CheckID:     "git:dirty_repo",
			Title:       fmt.Sprintf("Dirty repository: %s (uncommitted changes)", info.RepoName),
			Severity:    model.SeverityLow,
			Evidence:    "git status --porcelain returned non-empty output",
			Remediation: "Review and commit or discard uncommitted changes.",
		}
		s.mu.Lock()
		s.findings = append(s.findings, finding)
		s.mu.Unlock()
	}

	return &asset
}

func (s *Source) totalSoftware() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sw := range s.software {
		n += len(sw)
	}
	return n
}

// applyLockfilePreference removes manifests from the list when a
// corresponding lockfile exists in the same directory.
func applyLockfilePreference(matches []WalkMatch) []WalkMatch {
	// Build set of (directory, manifest filename) pairs that have a lockfile.
	type dirFile struct{ dir, file string }
	skip := make(map[dirFile]struct{})

	for _, m := range matches {
		if m.IsGitDir {
			continue
		}
		base := filepath.Base(m.Path)
		if manifest, ok := parsers.LockfileOverrides[base]; ok {
			skip[dirFile{dir: filepath.Dir(m.Path), file: manifest}] = struct{}{}
		}
	}

	if len(skip) == 0 {
		return matches
	}

	filtered := make([]WalkMatch, 0, len(matches))
	for _, m := range matches {
		if m.IsGitDir {
			filtered = append(filtered, m)
			continue
		}
		base := filepath.Base(m.Path)
		if _, skipped := skip[dirFile{dir: filepath.Dir(m.Path), file: base}]; skipped {
			slog.Debug("manifest scanner: skipping manifest in favour of lockfile",
				"path", m.Path)
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

func manifestTags(path, ecosystem string, result *parsers.ParseResult) string {
	tags := map[string]any{
		"manifest_path": path,
		"ecosystem":     ecosystem,
		"dep_count":     len(result.Dependencies),
		"lockfile_used": result.LockfileUsed,
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

// resolveRoots returns the absolute, symlink-resolved versions of the given paths.
func resolveRoots(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			out = append(out, abs) // keep unresolved if symlink check fails
			continue
		}
		out = append(out, resolved)
	}
	return out
}

// isWithinRoots checks that path (after cleaning) is under at least one root.
func isWithinRoots(path string, roots []string) bool {
	cleaned := filepath.Clean(path)
	for _, root := range roots {
		if strings.HasPrefix(cleaned, root+string(filepath.Separator)) || cleaned == root {
			return true
		}
	}
	return false
}

func newID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New() // fallback to v4
	}
	return id
}

// sourceConfig holds parsed configuration for the manifests source.
type sourceConfig struct {
	policyEngine    *PolicyEngine
	excludeDirs     map[string]struct{}
	scanPaths       []string
	maxDepth        int
	maxFileSizeMB   int
	gitStaleDays    int
	preferLockfiles bool
	gitEnabled      bool
	gitDetectDirty  bool
}

var defaultExcludeDirs = []string{
	"node_modules", "vendor", ".git", "__pycache__", ".cache",
	".tox", ".venv", "venv", "target", "build", "dist",
	".gradle", ".m2",
}

func parseSourceConfig(cfg map[string]any) sourceConfig {
	sc := sourceConfig{
		scanPaths:       []string{"/opt", "/srv", "/var/www", "/home"},
		maxDepth:        10,
		maxFileSizeMB:   50,
		preferLockfiles: true,
		gitEnabled:      true,
		gitDetectDirty:  true,
		gitStaleDays:    30,
	}

	// Build default exclude dirs set.
	sc.excludeDirs = make(map[string]struct{}, len(defaultExcludeDirs))
	for _, d := range defaultExcludeDirs {
		sc.excludeDirs[d] = struct{}{}
	}

	if cfg == nil {
		return sc
	}

	if v, ok := cfg["scan_paths"]; ok {
		sc.scanPaths = toStringSlice(v)
	}
	if v, ok := cfg["max_depth"].(float64); ok {
		sc.maxDepth = int(v)
	}
	if v, ok := cfg["max_depth"].(int); ok {
		sc.maxDepth = v
	}
	if v, ok := cfg["max_file_size_mb"].(float64); ok {
		sc.maxFileSizeMB = int(v)
	}
	if v, ok := cfg["max_file_size_mb"].(int); ok {
		sc.maxFileSizeMB = v
	}
	if v, ok := cfg["follow_symlinks"].(bool); ok {
		_ = v // reserved for future use
	}
	if v, ok := cfg["prefer_lockfiles"].(bool); ok {
		sc.preferLockfiles = v
	}
	if v, ok := cfg["exclude_dirs"]; ok {
		dirs := toStringSlice(v)
		if len(dirs) > 0 {
			sc.excludeDirs = make(map[string]struct{}, len(dirs))
			for _, d := range dirs {
				sc.excludeDirs[d] = struct{}{}
			}
		}
	}

	// Git sub-config.
	if git, ok := cfg["git"].(map[string]any); ok {
		if v, ok := git["enabled"].(bool); ok {
			sc.gitEnabled = v
		}
		if v, ok := git["detect_dirty"].(bool); ok {
			sc.gitDetectDirty = v
		}
		if v, ok := git["detect_stale_days"].(float64); ok {
			sc.gitStaleDays = int(v)
		}
		if v, ok := git["detect_stale_days"].(int); ok {
			sc.gitStaleDays = v
		}
	}

	// Policy sub-config.
	if policyCfg, ok := cfg["policy"].(map[string]any); ok {
		pc := PolicyConfig{}
		if v, ok := policyCfg["mode"].(string); ok {
			pc.Mode = v
		}
		if bl, ok := policyCfg["blocklist"].([]any); ok {
			for _, entry := range bl {
				if m, ok := entry.(map[string]any); ok {
					rule := BlocklistRule{}
					if v, ok := m["name"].(string); ok {
						rule.Name = v
					}
					if v, ok := m["version"].(string); ok {
						rule.Version = v
					}
					if v, ok := m["reason"].(string); ok {
						rule.Reason = v
					}
					if v, ok := m["remediation"].(string); ok {
						rule.Remediation = v
					}
					pc.Blocklist = append(pc.Blocklist, rule)
				}
			}
		}
		if al, ok := policyCfg["allowlist"].([]any); ok {
			for _, entry := range al {
				if m, ok := entry.(map[string]any); ok {
					rule := AllowlistRule{}
					if v, ok := m["name"].(string); ok {
						rule.Name = v
					}
					pc.Allowlist = append(pc.Allowlist, rule)
				}
			}
		}
		sc.policyEngine = NewPolicyEngine(pc)
	}

	return sc
}

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
