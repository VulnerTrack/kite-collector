package editorext

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// discoverHomes returns the absolute paths of every user home directory
// on the host. The kite-collector agent typically runs as a service so
// we don't know which user is "the user" — we walk every subdirectory of
// /home (Linux), /Users (macOS), C:\Users (Windows). Excludes system
// accounts. Shared with browserext via the same convention.
func discoverHomes() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return listHomes("/home")
	case "darwin":
		return listHomes("/Users")
	case "windows":
		users := os.Getenv("SystemDrive") + `\Users`
		if users == `\Users` {
			users = `C:\Users`
		}
		return listHomes(users)
	}
	return nil
}

func listHomes(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
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

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
