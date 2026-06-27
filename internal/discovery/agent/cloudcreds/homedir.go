package cloudcreds

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// defaultHomeRoots returns the per-OS directories whose immediate
// subdirectories are user homes. Same convention as the SSH-keys /
// browser-extensions / editor-extensions collectors.
func defaultHomeRoots() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []string{"/home", "/root"}
	case "darwin":
		return []string{"/Users", "/var/root"}
	case "windows":
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users`}
	}
	return nil
}

// walkHomes returns every user home directory under roots, skipping
// system users. Uses the injected readDir to keep tests hermetic.
func walkHomes(readDir func(string) ([]os.DirEntry, error), roots []string) []string {
	var out []string
	for _, root := range roots {
		entries, err := readDir(root)
		if err != nil {
			// /root is sometimes the path itself, not a parent — treat
			// as a single home when the immediate ReadDir fails.
			if base := filepath.Base(root); base == "root" || base == "var" {
				out = append(out, root)
			}
			continue
		}
		// If the root itself looks like a single user home (e.g.
		// /root), include it.
		if filepath.Base(root) == "root" {
			out = append(out, root)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			if isSystemUserName(name) {
				continue
			}
			out = append(out, filepath.Join(root, name))
		}
	}
	return out
}

func isSystemUserName(name string) bool {
	switch strings.ToLower(name) {
	case "shared", "guest", "public", "default", "all users",
		"defaultappuser", "defaultaccount", "wdagutilityaccount":
		return true
	}
	return false
}
