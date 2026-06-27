package shellinit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// fileCollector walks every user home + the system-wide directories
// for known init-file basenames. The (basename, shell, role) mapping is
// static — adding a new shell is a one-liner in shellInitFiles().
type fileCollector struct {
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	homeRoots   []string
	systemFiles []systemInit
	dropInDirs  []dropInDir
}

type systemInit struct {
	path  string
	shell Shell
	role  FileRole
}

type dropInDir struct {
	dir      string
	shell    Shell
	suffixOK []string
}

// NewCollector returns the default shell-init walker for the current OS.
func NewCollector() Collector {
	return &fileCollector{
		homeRoots:   defaultHomeRoots(),
		systemFiles: defaultSystemFiles(),
		dropInDirs:  defaultDropInDirs(),
		readFile:    func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME / /etc paths
		readDir:     func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "shell-init-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]InitFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []InitFile

	// User-scoped: walk every home for known basenames.
	for _, root := range c.homeRoots {
		users, err := c.readDir(root)
		if err != nil {
			continue
		}
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			if isSystemUserName(u.Name()) {
				continue
			}
			home := filepath.Join(root, u.Name())
			out = append(out, c.collectUserHome(u.Name(), home)...)
			if len(out) >= MaxFiles {
				break
			}
		}
	}

	// System-scoped: fixed file list + drop-in directories.
	for _, sf := range c.systemFiles {
		f, ok := c.readAndParse(sf.path, "", ScopeSystem, sf.shell, sf.role)
		if ok {
			out = append(out, f)
		}
	}
	for _, d := range c.dropInDirs {
		entries, err := c.readDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !hasAnySuffix(e.Name(), d.suffixOK) {
				continue
			}
			path := filepath.Join(d.dir, e.Name())
			f, ok := c.readAndParse(path, "", ScopeSystem, d.shell, RoleDropIn)
			if ok {
				out = append(out, f)
			}
		}
	}

	if len(out) > MaxFiles {
		out = out[:MaxFiles]
	}
	SortInitFiles(out)
	return out, nil
}

func (c *fileCollector) collectUserHome(user, home string) []InitFile {
	var out []InitFile
	for _, spec := range shellInitFiles() {
		path := filepath.Join(home, spec.basename)
		f, ok := c.readAndParse(path, user, ScopeUser, spec.shell, spec.role)
		if ok {
			out = append(out, f)
		}
	}
	// Fish config lives at a nested path.
	fishPath := filepath.Join(home, ".config", "fish", "config.fish")
	if f, ok := c.readAndParse(fishPath, user, ScopeUser, ShellFish, RoleRC); ok {
		out = append(out, f)
	}
	return out
}

// readAndParse reads path, parses it, and stamps the metadata fields.
// Returns (zero, false) when the file doesn't exist or can't be read.
func (c *fileCollector) readAndParse(path, owner string, scope Scope, shell Shell, role FileRole) (InitFile, bool) {
	data, err := c.readFile(path)
	if err != nil {
		return InitFile{}, false
	}
	f := Parse(data)
	f.FilePath = path
	f.OwnerUser = owner
	f.Scope = scope
	f.Shell = shell
	f.FileRole = role
	return f, true
}

// initSpec maps a per-home basename to its shell + role.
type initSpec struct {
	basename string
	shell    Shell
	role     FileRole
}

func shellInitFiles() []initSpec {
	return []initSpec{
		{".bashrc", ShellBash, RoleRC},
		{".bash_profile", ShellBash, RoleProfile},
		{".bash_login", ShellBash, RoleLogin},
		{".bash_logout", ShellBash, RoleLogout},
		{".profile", ShellSh, RoleProfile},
		{".zshrc", ShellZsh, RoleRC},
		{".zprofile", ShellZsh, RoleProfile},
		{".zlogin", ShellZsh, RoleLogin},
		{".zlogout", ShellZsh, RoleLogout},
		{".zshenv", ShellZsh, RoleEnv},
		{".cshrc", ShellCsh, RoleRC},
		{".tcshrc", ShellTcsh, RoleRC},
		{".kshrc", ShellKsh, RoleRC},
	}
}

func defaultSystemFiles() []systemInit {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []systemInit{
			{"/etc/profile", ShellSh, RoleProfile},
			{"/etc/bashrc", ShellBash, RoleRC},
			{"/etc/bash.bashrc", ShellBash, RoleRC},
			{"/etc/zsh/zshrc", ShellZsh, RoleRC},
			{"/etc/zsh/zprofile", ShellZsh, RoleProfile},
			{"/etc/zsh/zlogin", ShellZsh, RoleLogin},
			{"/etc/zshrc", ShellZsh, RoleRC},
			{"/etc/csh.cshrc", ShellCsh, RoleRC},
			{"/etc/csh.login", ShellCsh, RoleLogin},
		}
	case "darwin":
		return []systemInit{
			{"/etc/profile", ShellSh, RoleProfile},
			{"/etc/bashrc", ShellBash, RoleRC},
			{"/etc/zshrc", ShellZsh, RoleRC},
			{"/etc/zprofile", ShellZsh, RoleProfile},
			{"/etc/csh.cshrc", ShellCsh, RoleRC},
		}
	}
	return nil
}

func defaultDropInDirs() []dropInDir {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []dropInDir{
			{"/etc/profile.d", ShellSh, []string{".sh"}},
			{"/etc/bashrc.d", ShellBash, []string{".sh", ".bashrc"}},
			{"/etc/zsh/zshrc.d", ShellZsh, []string{".zsh"}},
		}
	}
	return nil
}

func defaultHomeRoots() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []string{"/home", "/root"}
	case "darwin":
		return []string{"/Users", "/var/root"}
	}
	return nil
}

func isSystemUserName(name string) bool {
	switch strings.ToLower(name) {
	case "shared", "guest", "public", "default":
		return true
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}
