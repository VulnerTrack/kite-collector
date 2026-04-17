// Package code provides a discovery source that finds code repositories on
// the local filesystem and surfaces them as repository assets.
package code

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Source discovers git repositories rooted at one or more configured paths
// and returns each repository as a model.AssetTypeRepository asset.
type Source struct{}

// New returns a new code discovery source.
func New() *Source { return &Source{} }

// Name returns the stable source identifier used in configuration and metrics.
func (s *Source) Name() string { return "code" }

// Discover walks each path listed in cfg["paths"] and returns one asset per
// git repository found. A git repository is any directory that contains a
// ".git" sub-entry.
//
// cfg keys:
//
//	paths      []string  directories to search (required)
//	max_depth  int       how many directory levels to descend (default: 3)
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	paths := extractPaths(cfg)
	if len(paths) == 0 {
		slog.Debug("code source: no paths configured, skipping")
		return nil, nil
	}

	maxDepth := 3
	if v, ok := cfg["max_depth"]; ok {
		switch d := v.(type) {
		case int:
			maxDepth = d
		case float64:
			maxDepth = int(d)
		}
	}

	now := time.Now().UTC()
	var assets []model.Asset
	seen := make(map[string]bool) // deduplicate by absolute path

	for _, root := range paths {
		abs, err := filepath.Abs(root)
		if err != nil {
			slog.Warn("code source: cannot resolve path", "path", root, "error", err)
			continue
		}

		repos, err := findRepos(ctx, abs, maxDepth)
		if err != nil {
			slog.Warn("code source: walk failed", "path", abs, "error", err)
			continue
		}

		for _, repoPath := range repos {
			if seen[repoPath] {
				continue
			}
			seen[repoPath] = true

			tags, _ := json.Marshal(map[string]string{
				"path": repoPath,
				"vcs":  "git",
			})

			a := model.Asset{
				ID:              uuid.Must(uuid.NewV7()),
				AssetType:       model.AssetTypeRepository,
				Hostname:        filepath.Base(repoPath),
				DiscoverySource: "code",
				FirstSeenAt:     now,
				LastSeenAt:      now,
				Tags:            string(tags),
			}
			a.ComputeNaturalKey()
			assets = append(assets, a)
		}
	}

	slog.Info("code source: discovery complete", "repos", len(assets))
	return assets, nil
}

// findRepos walks root up to maxDepth levels and collects directories that
// contain a ".git" entry. The walk does not descend into found repositories.
func findRepos(ctx context.Context, root string, maxDepth int) ([]string, error) {
	var repos []string

	err := walk(ctx, root, 0, maxDepth, func(path string) {
		repos = append(repos, path)
	})

	return repos, err
}

// walk recurses into dir up to depth levels, calling found when a git repo is
// detected. It stops descending into a directory once it is identified as a
// git repository.
func walk(ctx context.Context, dir string, depth, maxDepth int, found func(string)) error {
	if depth > maxDepth {
		return nil
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("code walk cancelled: %w", ctx.Err())
	default:
	}

	// Check if this directory is a git repo.
	if isGitRepo(dir) {
		found(dir)
		return nil // don't descend into nested repos
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsPermission(err) {
			slog.Debug("code source: permission denied, skipping", "path", dir)
			return nil
		}
		return fmt.Errorf("read dir %s: %w", dir, err)
	}

	for _, e := range entries {
		if !e.IsDir() || isHiddenOrSystem(e.Name()) {
			continue
		}
		child := filepath.Join(dir, e.Name())
		if err := walk(ctx, child, depth+1, maxDepth, found); err != nil {
			return err
		}
	}

	return nil
}

// isGitRepo returns true if dir contains a ".git" entry.
func isGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// isHiddenOrSystem returns true for directory names that should be skipped
// during recursive walks (hidden dirs, node_modules, vendor, etc.).
func isHiddenOrSystem(name string) bool {
	if len(name) > 0 && name[0] == '.' {
		return true
	}
	switch name {
	case "node_modules", "vendor", "__pycache__", ".git",
		"target", "dist", "build", ".cache":
		return true
	}
	return false
}

// extractPaths reads the "paths" key from cfg as a string slice.
func extractPaths(cfg map[string]any) []string {
	v, ok := cfg["paths"]
	if !ok {
		return nil
	}

	switch p := v.(type) {
	case []string:
		return p
	case []any:
		paths := make([]string, 0, len(p))
		for _, item := range p {
			if s, ok := item.(string); ok && s != "" {
				paths = append(paths, s)
			}
		}
		return paths
	case string:
		if p != "" {
			return []string{p}
		}
	}
	return nil
}
