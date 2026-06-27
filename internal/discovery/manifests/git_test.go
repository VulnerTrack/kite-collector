package manifests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectGitRepo_BasicMetadata(t *testing.T) {
	// Create a minimal .git directory structure.
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755))

	// HEAD points to main branch.
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	// main ref points to a commit.
	writeFile(t, filepath.Join(gitDir, "refs", "heads", "main"), "abc123def456\n")
	// Git config with remote origin.
	writeFile(t, filepath.Join(gitDir, "config"), `[core]
	bare = false
[remote "origin"]
	url = https://github.com/acme/myapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`)

	info, err := DetectGitRepo(context.Background(), gitDir, false, 0)
	require.NoError(t, err)

	assert.Equal(t, root, info.Path)
	assert.Equal(t, "main", info.Branch)
	assert.Equal(t, "abc123def456", info.HeadCommit)
	assert.Equal(t, "https://github.com/acme/myapp.git", info.RemoteURL)
	assert.Equal(t, "myapp", info.RepoName)
}

func TestDetectGitRepo_DetachedHEAD(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))

	writeFile(t, filepath.Join(gitDir, "HEAD"), "deadbeef1234567890\n")

	info, err := DetectGitRepo(context.Background(), gitDir, false, 0)
	require.NoError(t, err)

	assert.Equal(t, "(detached)", info.Branch)
	assert.Equal(t, "deadbeef1234567890", info.HeadCommit)
}

func TestDetectGitRepo_PackedRefs(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))

	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/develop\n")
	// No loose ref file — commit is in packed-refs.
	writeFile(t, filepath.Join(gitDir, "packed-refs"), `# pack-refs with: peeled fully-peeled sorted
fedcba9876543210 refs/heads/develop
`)

	info, err := DetectGitRepo(context.Background(), gitDir, false, 0)
	require.NoError(t, err)

	assert.Equal(t, "develop", info.Branch)
	assert.Equal(t, "fedcba9876543210", info.HeadCommit)
}

func TestStripCredentials(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"https://user:token@github.com/acme/repo.git",
			"https://github.com/acme/repo.git",
		},
		{
			"https://github.com/acme/repo.git",
			"https://github.com/acme/repo.git",
		},
		{
			"git@github.com:acme/repo.git",
			"git@github.com:acme/repo.git",
		},
	}
	for _, tc := range tests {
		got := stripCredentials(tc.input)
		assert.Equal(t, tc.expected, got, "input: %s", tc.input)
	}
}

func TestRepoNameFromURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://github.com/acme/myapp.git", "myapp"},
		{"git@github.com:acme/myapp.git", "myapp"},
		{"https://github.com/acme/myapp", "myapp"},
		{"", ""},
	}
	for _, tc := range tests {
		got := repoNameFromURL(tc.input)
		assert.Equal(t, tc.expected, got, "input: %s", tc.input)
	}
}

func TestDetectGitRepo_SSHRemoteURL(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))

	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(gitDir, "config"), `[remote "origin"]
	url = git@github.com:acme/backend.git
`)

	info, err := DetectGitRepo(context.Background(), gitDir, false, 0)
	require.NoError(t, err)

	assert.Equal(t, "git@github.com:acme/backend.git", info.RemoteURL)
	assert.Equal(t, "backend", info.RepoName)
}
