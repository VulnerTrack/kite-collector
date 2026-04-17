package manifests

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// WalkMatch represents a single item discovered during a filesystem walk.
type WalkMatch struct {
	Path     string // absolute path to the file or .git directory
	IsGitDir bool   // true when this entry is a .git/ directory
}

// WalkerConfig controls the filesystem walk behaviour.
type WalkerConfig struct {
	ExcludeDirs      map[string]struct{}
	Filenames        map[string]struct{} // exact base-name matches
	ScanPaths        []string
	GlobPatterns     []string // glob patterns (e.g. "*.csproj")
	MaxDepth         int
	MaxFileSizeBytes int64
	DetectGit        bool
}

// Walk traverses the configured root paths and calls fn for every manifest
// file or .git directory it finds.  The walk respects depth limits, exclusion
// patterns, symlink safety, file-size limits and context cancellation.
func Walk(ctx context.Context, cfg WalkerConfig, fn func(WalkMatch) error) error {
	for _, root := range cfg.ScanPaths {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("walk cancelled: %w", err)
		}

		info, err := os.Lstat(root)
		if err != nil {
			slog.Warn("manifest walker: root path inaccessible",
				"path", root, "error", err)
			continue
		}
		if !info.IsDir() {
			slog.Warn("manifest walker: root path is not a directory",
				"path", root)
			continue
		}

		if err := walkRoot(ctx, root, cfg, fn); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("walk cancelled: %w", ctxErr)
			}
			slog.Warn("manifest walker: walk error",
				"root", root, "error", err)
		}
	}
	return nil
}

func walkRoot(ctx context.Context, root string, cfg WalkerConfig, fn func(WalkMatch) error) error {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Debug("manifest walker: entry error",
				"path", path, "error", err)
			return nil // skip inaccessible entries
		}

		// Check context on every entry for prompt cancellation.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Never follow symlinks.
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)

		if d.IsDir() {
			return handleDir(root, path, base, cfg, fn)
		}

		return handleFile(path, base, d, cfg, fn)
	})
	if err != nil {
		return fmt.Errorf("walk root %s: %w", root, err)
	}
	return nil
}

func handleDir(root, path, base string, cfg WalkerConfig, fn func(WalkMatch) error) error {
	// Skip self (root directory).
	if path == root {
		return nil
	}

	// Depth check: count path components relative to the root.
	depth := relativeDepth(root, path)
	if cfg.MaxDepth > 0 && depth > cfg.MaxDepth {
		return filepath.SkipDir
	}

	// Exclusion check.
	if _, excluded := cfg.ExcludeDirs[base]; excluded {
		return filepath.SkipDir
	}

	// Git repository detection.
	if cfg.DetectGit && base == ".git" {
		if err := fn(WalkMatch{Path: path, IsGitDir: true}); err != nil {
			return err
		}
		return filepath.SkipDir // never descend into .git/
	}

	return nil
}

func handleFile(path, base string, d fs.DirEntry, cfg WalkerConfig, fn func(WalkMatch) error) error {
	if !matchesFilename(base, cfg) {
		return nil
	}

	// File-size check.
	if cfg.MaxFileSizeBytes > 0 {
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if info.Size() > cfg.MaxFileSizeBytes {
			slog.Debug("manifest walker: skipping oversized file",
				"path", path, "size_bytes", info.Size())
			return nil
		}
	}

	return fn(WalkMatch{Path: path})
}

func matchesFilename(base string, cfg WalkerConfig) bool {
	if _, ok := cfg.Filenames[base]; ok {
		return true
	}
	for _, pat := range cfg.GlobPatterns {
		if matched, _ := filepath.Match(pat, base); matched {
			return true
		}
	}
	return false
}

// relativeDepth returns the number of path segments between root and path.
// root="/opt", path="/opt/app/src" → 2
func relativeDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}
