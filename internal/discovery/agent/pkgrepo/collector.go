package pkgrepo

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector walks every system + per-user repo file the package
// supports. Each file's parser is independent; failures on one
// (missing dir, unreadable file) don't sink the others.
type fileCollector struct {
	readFile        func(string) ([]byte, error)
	readDir         func(string) ([]os.DirEntry, error)
	aptSourcesList  string
	aptSourcesDir   string
	yumReposDir     string
	zyppReposDir    string
	apkRepositories string
	systemPipConf   string
	systemNpmrc     string
	userHomes       []string // for ~/.config/pip/pip.conf, ~/.npmrc, etc.
}

// NewCollector returns the default repo file walker. Caller can also
// build a *fileCollector directly when overriding any path or seam.
func NewCollector() Collector {
	return &fileCollector{
		aptSourcesList:  "/etc/apt/sources.list",
		aptSourcesDir:   "/etc/apt/sources.list.d",
		yumReposDir:     "/etc/yum.repos.d",
		zyppReposDir:    "/etc/zypp/repos.d",
		apkRepositories: "/etc/apk/repositories",
		systemPipConf:   "/etc/pip.conf",
		systemNpmrc:     "/etc/npmrc",
		userHomes:       discoverUserHomes(),
		readFile:        func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:         func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

// discoverUserHomes returns the home directories the current user can
// see. We probe /home and /Users; non-existent paths return empty.
func discoverUserHomes() []string {
	var out []string
	for _, base := range []string{"/home", "/Users"} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(base, e.Name()))
			}
		}
	}
	// Also include the current process's HOME — covers single-user
	// images that don't have /home populated.
	if home, _ := os.UserHomeDir(); home != "" {
		out = appendUnique(out, home)
	}
	return out
}

func appendUnique(ss []string, want string) []string {
	for _, s := range ss {
		if s == want {
			return ss
		}
	}
	return append(ss, want)
}

func (c *fileCollector) Name() string { return "pkgrepo-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Repo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Repo

	// -- APT -----------------------------------------------------------------
	if data, err := c.readFile(c.aptSourcesList); err == nil {
		out = append(out, ParseAPTSourcesList(data, c.aptSourcesList)...)
	}
	for _, p := range c.filesIn(c.aptSourcesDir) {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		switch {
		case strings.HasSuffix(p, ".list"):
			out = append(out, ParseAPTSourcesList(data, p)...)
		case strings.HasSuffix(p, ".sources"):
			out = append(out, ParseAPTDeb822(data, p)...)
		}
	}

	// -- yum / dnf -----------------------------------------------------------
	for _, p := range c.filesInWithSuffix(c.yumReposDir, ".repo") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseYumRepo(data, p, EcosystemDNF)...)
	}

	// -- zypper --------------------------------------------------------------
	for _, p := range c.filesInWithSuffix(c.zyppReposDir, ".repo") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseYumRepo(data, p, EcosystemZypper)...)
	}

	// -- apk -----------------------------------------------------------------
	if data, err := c.readFile(c.apkRepositories); err == nil {
		out = append(out, ParseAPKRepositories(data, c.apkRepositories)...)
	}

	// -- system pip / npm ----------------------------------------------------
	if data, err := c.readFile(c.systemPipConf); err == nil {
		out = append(out, ParsePipConfig(data, c.systemPipConf, "")...)
	}
	if data, err := c.readFile(c.systemNpmrc); err == nil {
		out = append(out, ParseNPMrc(data, c.systemNpmrc, "")...)
	}

	// -- per-user language configs ------------------------------------------
	for _, home := range c.userHomes {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		user := filepath.Base(home)
		out = append(out, c.walkUserHome(home, user)...)
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

// walkUserHome reads the well-known per-user package config files.
func (c *fileCollector) walkUserHome(home, user string) []Repo {
	var out []Repo
	candidates := []struct {
		parse func(raw []byte, filePath, user string) []Repo
		path  string
	}{
		{path: filepath.Join(home, ".config", "pip", "pip.conf"), parse: ParsePipConfig},
		{path: filepath.Join(home, ".pip", "pip.conf"), parse: ParsePipConfig},
		{path: filepath.Join(home, ".npmrc"), parse: ParseNPMrc},
		{path: filepath.Join(home, ".cargo", "config.toml"), parse: ParseCargoConfig},
		{path: filepath.Join(home, ".cargo", "config"), parse: ParseCargoConfig},
		{path: filepath.Join(home, ".gemrc"), parse: ParseGemrc},
	}
	for _, cand := range candidates {
		data, err := c.readFile(cand.path)
		if err != nil {
			slog.Debug("pkgrepo: per-user config unreadable",
				"path", cand.path, "error", err)
			continue
		}
		out = append(out, cand.parse(data, cand.path, user)...)
	}
	return out
}

// filesIn returns the lexically-sorted absolute paths of regular files
// in dir.
func (c *fileCollector) filesIn(dir string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(dir, n))
	}
	return out
}

// filesInWithSuffix is filesIn with an extra suffix filter.
func (c *fileCollector) filesInWithSuffix(dir, suffix string) []string {
	var out []string
	for _, p := range c.filesIn(dir) {
		if strings.HasSuffix(p, suffix) {
			out = append(out, p)
		}
	}
	return out
}
