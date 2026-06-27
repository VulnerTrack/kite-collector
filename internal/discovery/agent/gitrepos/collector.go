package gitrepos

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// fileCollector walks a curated set of root directories looking for
// .git markers. Sources covered (in order):
//
//   - /home/<user>            (Linux)
//   - /Users/<user>           (macOS)
//   - /root                   (root-owned clones)
//   - /opt
//   - /srv
//   - /var/www
//   - /var/lib/git            (bare-repo conventional path)
//
// Cross-OS: the same walker handles Windows (C:\Users\<user>) when
// the agent's userHomes list is populated by the parent runtime.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (fs.FileInfo, error)
	skipDirSet map[string]bool
	roots      []string
	maxDepth   int
}

// NewCollector returns the default git-repo walker.
func NewCollector() Collector {
	return &fileCollector{
		roots:    DefaultRoots(),
		maxDepth: 6, // /home/alice/code/foo/bar/baz/.git is plenty
		skipDirSet: map[string]bool{
			"node_modules": true,
			"vendor":       true,
			"target":       true,
			".cache":       true,
			".cargo":       true,
			".rustup":      true,
			"venv":         true,
			".venv":        true,
			"__pycache__":  true,
			".gradle":      true,
			".m2":          true,
			".npm":         true,
		},
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- collector walks predictable roots
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
		statFile: func(p string) (fs.FileInfo, error) { return os.Stat(p) },
	}
}

// DefaultRoots returns the conventional locations to walk when looking
// for git working trees.
func DefaultRoots() []string {
	roots := []string{
		"/root", "/opt", "/srv", "/var/www", "/var/lib/git",
	}
	// Add every user home under /home + /Users.
	for _, base := range []string{"/home", "/Users"} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				roots = append(roots, filepath.Join(base, e.Name()))
			}
		}
	}
	if home, _ := os.UserHomeDir(); home != "" {
		// Dedupe.
		seen := false
		for _, r := range roots {
			if r == home {
				seen = true
				break
			}
		}
		if !seen {
			roots = append(roots, home)
		}
	}
	return roots
}

func (c *fileCollector) Name() string { return "gitrepos-walker" }

func (c *fileCollector) Collect(ctx context.Context) ([]Repo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var (
		out  []Repo
		seen = make(map[string]bool) // dedupe by git_dir
	)

	for _, root := range c.roots {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		c.walkRoot(ctx, root, &out, seen)
		if len(out) >= MaxRepos {
			break
		}
	}

	if len(out) > MaxRepos {
		out = out[:MaxRepos]
	}
	SortRepos(out)
	return out, nil
}

// walkRoot recursively descends `root` looking for `.git/` markers.
// Each hit triggers parseRepo; the walker then skips into the matched
// repo's children (no nested repos at sub-tree of a parent repo's
// working tree — git itself disallows that).
func (c *fileCollector) walkRoot(ctx context.Context, root string, out *[]Repo, seen map[string]bool) {
	type frame struct {
		path  string
		depth int
	}
	stack := []frame{{root, 0}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.depth > c.maxDepth {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		entries, err := c.readDir(f.path)
		if err != nil {
			continue
		}
		// Is there a .git here? Two shapes: a directory, or a `gitdir:`
		// pointer file (worktrees + submodules).
		for _, e := range entries {
			name := e.Name()
			if name != ".git" {
				continue
			}
			gitDir := filepath.Join(f.path, ".git")
			if !e.IsDir() {
				// Pointer file `gitdir: ../.git/worktrees/branch`
				resolved := c.resolveGitDirPointer(gitDir)
				if resolved != "" {
					gitDir = resolved
				}
			}
			if seen[gitDir] {
				break
			}
			seen[gitDir] = true
			c.parseRepo(f.path, gitDir, out)
			if len(*out) >= MaxRepos {
				return
			}
			// Don't descend into this repo's working tree any further.
			return
		}
		// Descend into subdirs (sorted for stable diffs).
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if c.skipDirSet[name] {
				continue
			}
			// Skip hidden dirs except .git (handled above).
			if strings.HasPrefix(name, ".") {
				continue
			}
			stack = append(stack, frame{filepath.Join(f.path, name), f.depth + 1})
		}
	}
}

// resolveGitDirPointer reads a `.git` pointer file (used by git
// worktrees + submodules) and returns the absolute path it points at.
func (c *fileCollector) resolveGitDirPointer(pointerPath string) string {
	data, err := c.readFile(pointerPath)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if target == "" {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(pointerPath), target)
	}
	return filepath.Clean(target)
}

// parseRepo reads the repo's config + HEAD + hooks dir and emits one
// Repo row per remote (or one row with empty remote when no remotes
// are configured).
func (c *fileCollector) parseRepo(workTree, gitDir string, out *[]Repo) {
	configPath := filepath.Join(gitDir, "config")
	data, err := c.readFile(configPath)
	if err != nil {
		slog.Debug("gitrepos: config unreadable", "path", configPath, "error", err)
		return
	}
	snap := ParseConfig(data)
	hash := HashContents(data)

	// HEAD: best-effort.
	head := ""
	if h, herr := c.readFile(filepath.Join(gitDir, "HEAD")); herr == nil {
		head = ParseHead(h)
	}

	// Hooks: list every executable file under .git/hooks/ that isn't
	// a .sample shipped by git.
	hooks := c.executableHooks(filepath.Join(gitDir, "hooks"))

	// Config file mode + owner.
	var configMode, ownerUID int
	if info, serr := c.statFile(configPath); serr == nil {
		configMode = int(info.Mode().Perm())
		ownerUID = ownerUIDOf(info)
	}

	base := Repo{
		RepoPath:         workTree,
		GitDir:           gitDir,
		IsBare:           snap.IsBare,
		HeadBranch:       head,
		UserEmail:        snap.UserEmail,
		UserName:         snap.UserName,
		CredentialHelper: snap.CredentialHelper,
		SSHCommand:       snap.SSHCommand,
		InsteadOfPairs:   append([]string(nil), snap.InsteadOfPairs...),
		ExecutableHooks:  hooks,
		ConfigMode:       configMode,
		OwnerUID:         ownerUID,
		FilePath:         configPath,
		FileHash:         hash,
	}

	if len(snap.Remotes) == 0 {
		// Emit one row with empty remote to capture the repo's existence.
		AnnotateSecurity(&base)
		*out = append(*out, base)
		return
	}
	for name, u := range snap.Remotes {
		r := base
		r.RemoteName = name
		r.RemoteURL = u
		AnnotateSecurity(&r)
		*out = append(*out, r)
		if len(*out) >= MaxRepos {
			return
		}
	}
}

// executableHooks returns the names of files under `dir` that are
// executable AND not git-shipped `.sample` template names.
func (c *fileCollector) executableHooks(dir string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip the .sample templates git ships.
		if strings.HasSuffix(name, ".sample") {
			continue
		}
		info, err := c.statFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		// Any exec bit set on any class.
		if mode&0o111 == 0 {
			continue
		}
		// Only flag files that look like genuine hook names (the
		// curated set + custom-named files). We don't filter to
		// just default names — custom hook names with executable
		// bits are the most suspicious case.
		out = append(out, name)
	}
	return out
}
