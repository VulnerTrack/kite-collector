package manifests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalk_FindsManifests(t *testing.T) {
	root := t.TempDir()
	// Create a project structure.
	mkdirAll(t, root, "myapp")
	writeFile(t, filepath.Join(root, "myapp", "package.json"), `{}`)
	writeFile(t, filepath.Join(root, "myapp", "go.mod"), `module test`)

	cfg := WalkerConfig{
		ScanPaths: []string{root},
		MaxDepth:  10,
		Filenames: map[string]struct{}{"package.json": {}, "go.mod": {}},
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, matches, 2)
}

func TestWalk_RespectsMaxDepth(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, root, "a", "b", "c", "d")
	writeFile(t, filepath.Join(root, "a", "package.json"), `{}`)
	writeFile(t, filepath.Join(root, "a", "b", "c", "d", "package.json"), `{}`)

	cfg := WalkerConfig{
		ScanPaths: []string{root},
		MaxDepth:  2,
		Filenames: map[string]struct{}{"package.json": {}},
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, matches, 1, "only depth=1 file should be found")
}

func TestWalk_RespectsExcludeDirs(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, root, "app")
	mkdirAll(t, root, "node_modules", "dep")
	writeFile(t, filepath.Join(root, "app", "package.json"), `{}`)
	writeFile(t, filepath.Join(root, "node_modules", "dep", "package.json"), `{}`)

	cfg := WalkerConfig{
		ScanPaths:   []string{root},
		MaxDepth:    10,
		Filenames:   map[string]struct{}{"package.json": {}},
		ExcludeDirs: map[string]struct{}{"node_modules": {}},
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Contains(t, matches[0].Path, "app")
}

func TestWalk_DetectsGitDir(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, root, "repo", ".git")
	writeFile(t, filepath.Join(root, "repo", ".git", "HEAD"), "ref: refs/heads/main\n")

	cfg := WalkerConfig{
		ScanPaths: []string{root},
		MaxDepth:  10,
		DetectGit: true,
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.True(t, matches[0].IsGitDir)
}

func TestWalk_SkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), string(make([]byte, 2048)))

	cfg := WalkerConfig{
		ScanPaths:        []string{root},
		MaxDepth:         10,
		MaxFileSizeBytes: 1024,
		Filenames:        map[string]struct{}{"package.json": {}},
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestWalk_ContextCancellation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := WalkerConfig{
		ScanPaths: []string{root},
		MaxDepth:  10,
		Filenames: map[string]struct{}{"package.json": {}},
	}

	err := Walk(ctx, cfg, func(_ WalkMatch) error { return nil })
	assert.ErrorIs(t, err, context.Canceled)
}

func TestWalk_GlobPatterns(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "MyApp.csproj"), `<Project/>`)

	cfg := WalkerConfig{
		ScanPaths:    []string{root},
		MaxDepth:     10,
		GlobPatterns: []string{"*.csproj"},
	}

	var matches []WalkMatch
	err := Walk(context.Background(), cfg, func(m WalkMatch) error {
		matches = append(matches, m)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestWalk_SkipsNonexistentRoot(t *testing.T) {
	cfg := WalkerConfig{
		ScanPaths: []string{"/nonexistent/path/that/does/not/exist"},
		MaxDepth:  10,
	}

	err := Walk(context.Background(), cfg, func(_ WalkMatch) error { return nil })
	assert.NoError(t, err, "nonexistent roots should be skipped, not fatal")
}

// helpers

func mkdirAll(t *testing.T, parts ...string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(parts...), 0o755))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
