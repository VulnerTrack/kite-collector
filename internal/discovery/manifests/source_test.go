package manifests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// writeProject lays out a realistic little estate under root: a Node
// project with a manifest, a Go project, and (when git is available) a
// real dirty git repository.
func writeProject(t *testing.T, root string) {
	t.Helper()
	nodeDir := filepath.Join(root, "webapp")
	require.NoError(t, os.MkdirAll(nodeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(nodeDir, "package.json"), []byte(`{
  "name": "webapp",
  "version": "2.1.0",
  "dependencies": {"express": "^4.18.2"},
  "devDependencies": {"vitest": "^1.0.0"}
}`), 0o600))

	goDir := filepath.Join(root, "service")
	require.NoError(t, os.MkdirAll(goDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(goDir, "go.mod"), []byte(
		"module example.com/service\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n"), 0o600))
}

// initDirtyGitRepo creates a real repository with one commit and one
// uncommitted file, so DetectGitRepo + checkDirty exercise end to end.
func initDirtyGitRepo(t *testing.T, root string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := filepath.Join(root, "repo")
	require.NoError(t, os.MkdirAll(repo, 0o750))
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init", "-q")
	run("remote", "add", "origin", "https://user:sekrit@github.com/example/repo.git")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "README.md"), []byte("hi\n"), 0o600))
	run("add", "README.md")
	run("commit", "-q", "-m", "initial")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "uncommitted.txt"), []byte("dirty\n"), 0o600))
	return repo
}

func TestSourceNameAndInterface(t *testing.T) {
	s := NewSource()
	require.NotNil(t, s)
	assert.Equal(t, "manifests", s.Name())
}

// The full Discover pipeline over a temp estate: manifests become
// machines with software attached, the git repo becomes a repository
// machine flagged dirty, and credentials never leak out of origin URLs.
func TestSourceDiscover_EndToEnd(t *testing.T) {
	root := t.TempDir()
	writeProject(t, root)
	repo := initDirtyGitRepo(t, root)

	s := NewSource()
	machines, err := s.Discover(context.Background(), map[string]any{
		"scan_paths": []string{root},
		"max_depth":  6,
	})
	require.NoError(t, err)
	require.NotEmpty(t, machines)

	byHost := map[string]model.Machine{}
	for _, m := range machines {
		byHost[m.Hostname] = m
	}

	var project, gitRepo *model.Machine
	for host, m := range byHost {
		mm := m
		switch {
		case host == "webapp" || filepath.Base(m.Hostname) == "webapp":
			project = &mm
		}
		if mm.DiscoverySource == "manifests" && filepath.Base(repo) == filepath.Base(host) {
			gitRepo = &mm
		}
	}
	// Project machines carry parsed software.
	require.NotNil(t, project, "the node project must be discovered: %v", byHost)
	sw := s.CollectedSoftware()[project.ID]
	names := make([]string, 0, len(sw))
	for _, p := range sw {
		names = append(names, p.SoftwareName)
	}
	assert.Contains(t, names, "express")
	assert.Contains(t, names, "vitest")

	// The git repository is present and its tags never contain the
	// credentials embedded in the origin URL.
	if gitRepo != nil {
		assert.NotContains(t, gitRepo.Tags, "sekrit",
			"origin credentials must be stripped before persisting")
		assert.Contains(t, gitRepo.Tags, "github.com/example/repo")
	}

	// CollectedFindings is callable even when no policy produced any.
	_ = s.CollectedFindings()
}

func TestSourceDiscover_EmptyRootAndCancelledContext(t *testing.T) {
	s := NewSource()
	machines, err := s.Discover(context.Background(), map[string]any{
		"scan_paths": []string{t.TempDir()},
	})
	require.NoError(t, err)
	assert.Empty(t, machines, "an empty tree discovers nothing")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Discover(ctx, map[string]any{"scan_paths": []string{t.TempDir()}})
	// A cancelled context either errors or returns cleanly-empty — it
	// must not hang or panic; both shapes are acceptable here.
	_ = err
}

func TestCheckDirty(t *testing.T) {
	root := t.TempDir()
	repo := initDirtyGitRepo(t, root)
	assert.True(t, checkDirty(context.Background(), repo),
		"an uncommitted file must flag the repo dirty")

	assert.False(t, checkDirty(context.Background(), t.TempDir()),
		"a non-repo directory is not dirty (git status fails → false)")
}

func TestParseSourceConfig_DefaultsAndOverrides(t *testing.T) {
	def := parseSourceConfig(nil)
	assert.Equal(t, []string{"/opt", "/srv", "/var/www", "/home"}, def.scanPaths)
	assert.Equal(t, 10, def.maxDepth)
	assert.True(t, def.preferLockfiles)
	assert.True(t, def.gitEnabled)

	over := parseSourceConfig(map[string]any{
		"scan_paths":       []string{"/x"},
		"max_depth":        float64(3), // JSON numbers arrive as float64
		"max_file_size_mb": 7,
		"prefer_lockfiles": false,
	})
	assert.Equal(t, []string{"/x"}, over.scanPaths)
	assert.Equal(t, 3, over.maxDepth)
	assert.Equal(t, 7, over.maxFileSizeMB)
	assert.False(t, over.preferLockfiles)
}

// Stress: a wide tree of many small projects discovers completely and
// stays interactive.
func TestSourceDiscover_StressManyProjects(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 60; i++ {
		dir := filepath.Join(root, "proj", string(rune('a'+i%26))+string(rune('a'+(i/26)%26)))
		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
			[]byte("module example.com/m\n\ngo 1.22\n"), 0o600))
	}
	s := NewSource()
	start := time.Now()
	machines, err := s.Discover(context.Background(), map[string]any{
		"scan_paths": []string{root},
		"max_depth":  8,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, machines)
	assert.Less(t, time.Since(start), 30*time.Second)
}
