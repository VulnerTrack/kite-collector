package manifests

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GitRepoInfo holds metadata about a discovered git repository.
type GitRepoInfo struct {
	LastCommitDate time.Time // author date of HEAD commit
	RemoteURL      string    // origin remote URL (credentials stripped)
	Branch         string    // current branch name
	HeadCommit     string    // HEAD commit SHA
	RepoName       string    // derived from remote URL
	Path           string    // absolute path to the repo root (parent of .git)
	IsDirty        bool      // uncommitted changes detected
	IsStale        bool      // no commits within stale_days threshold
}

// DetectGitRepo reads metadata from a .git directory without shelling out
// to git for the core info. Optionally runs "git status" for dirty detection.
func DetectGitRepo(ctx context.Context, gitDir string, detectDirty bool, staleDays int) (*GitRepoInfo, error) {
	repoRoot := filepath.Dir(gitDir) // .git's parent is the repo root

	info := &GitRepoInfo{
		Path: repoRoot,
	}

	// 1. Read HEAD to get current ref or detached commit.
	head, err := readFileString(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return nil, fmt.Errorf("read .git/HEAD: %w", err)
	}
	head = strings.TrimSpace(head)

	if strings.HasPrefix(head, "ref: ") {
		ref := strings.TrimPrefix(head, "ref: ")
		info.Branch = branchFromRef(ref)
		// Resolve the ref to a commit SHA.
		info.HeadCommit = resolveRef(gitDir, ref)
	} else {
		// Detached HEAD — head is a commit SHA.
		info.HeadCommit = head
		info.Branch = "(detached)"
	}

	// 2. Read remote origin URL from .git/config.
	info.RemoteURL = readOriginURL(gitDir)
	info.RepoName = repoNameFromURL(info.RemoteURL)

	// 3. Determine last commit date from the commit object (best-effort).
	info.LastCommitDate = readCommitDate(ctx, gitDir, info.HeadCommit)

	// 4. Staleness check.
	if staleDays > 0 && !info.LastCommitDate.IsZero() {
		threshold := time.Now().UTC().AddDate(0, 0, -staleDays)
		info.IsStale = info.LastCommitDate.Before(threshold)
	}

	// 5. Dirty check (requires git binary on PATH).
	if detectDirty {
		info.IsDirty = checkDirty(ctx, repoRoot)
	}

	return info, nil
}

// branchFromRef extracts the branch name from a full ref path.
// "refs/heads/main" → "main"
func branchFromRef(ref string) string {
	const prefix = "refs/heads/"
	if strings.HasPrefix(ref, prefix) {
		return ref[len(prefix):]
	}
	return ref
}

// resolveRef reads the commit SHA for a symbolic ref, checking
// packed-refs if the loose ref file doesn't exist.
func resolveRef(gitDir, ref string) string {
	// Try loose ref first.
	refPath := filepath.Join(gitDir, ref)
	if data, err := readFileString(refPath); err == nil {
		return strings.TrimSpace(data)
	}

	// Fall back to packed-refs.
	packedPath := filepath.Join(gitDir, "packed-refs")
	data, err := os.ReadFile(packedPath) // #nosec G304 -- gitDir is walker-validated
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && parts[1] == ref {
			return parts[0]
		}
	}
	return ""
}

// readOriginURL parses [remote "origin"] url from .git/config.
func readOriginURL(gitDir string) string {
	cfgPath := filepath.Join(gitDir, "config")
	data, err := os.ReadFile(cfgPath) // #nosec G304 -- gitDir is walker-validated
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	inOrigin := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inOrigin = false
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url = ") {
			rawURL := strings.TrimPrefix(line, "url = ")
			return stripCredentials(strings.TrimSpace(rawURL))
		}
	}
	return ""
}

// stripCredentials removes user:password@ from HTTPS URLs.
func stripCredentials(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Not a parseable URL (e.g., SSH format git@host:repo.git).
		// Strip user@ from SSH URLs.
		if at := strings.Index(rawURL, "@"); at > 0 {
			if colon := strings.Index(rawURL[:at], ":"); colon > 0 {
				// Has user:pass@ — strip it.
				return rawURL[:colon] + rawURL[at+1:]
			}
		}
		return rawURL
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

// repoNameFromURL extracts the repository name from a remote URL.
// "https://github.com/acme/myapp.git" → "myapp"
// "git@github.com:acme/myapp.git" → "myapp"
func repoNameFromURL(remote string) string {
	if remote == "" {
		return ""
	}
	// Handle SSH format: git@host:owner/repo.git
	if i := strings.LastIndexByte(remote, ':'); i > 0 && !strings.Contains(remote, "://") {
		remote = remote[i+1:]
	}
	// Take the last path segment.
	if i := strings.LastIndexByte(remote, '/'); i >= 0 {
		remote = remote[i+1:]
	}
	return strings.TrimSuffix(remote, ".git")
}

// readCommitDate reads the author date from a loose commit object.
// Returns zero time on any failure.
func readCommitDate(ctx context.Context, gitDir, sha string) time.Time {
	if len(sha) < 4 {
		return time.Time{}
	}

	// Try reading the commit via git cat-file if available.
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return time.Time{}
	}

	cmd := exec.CommandContext(ctx, gitBin, "-C", filepath.Dir(gitDir), "log", "-1", "--format=%aI", sha) // #nosec G204 -- sha is a hex string from .git
	out, err := cmd.Output()
	if err != nil {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// checkDirty runs "git status --porcelain" to detect uncommitted changes.
func checkDirty(ctx context.Context, repoRoot string) bool {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return false // can't check without git
	}

	cmd := exec.CommandContext(ctx, gitBin, "-C", repoRoot, "status", "--porcelain") // #nosec G204 -- repoRoot is walker-validated
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path within .git dir
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}
