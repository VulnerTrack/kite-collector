// Binary loginventory walks every package containing a logcodes.go
// file and prints the rendered Markdown catalog to stdout.
//
// Usage:
//
//	go run ./tools/loginventory > docs/LOG_CODES.md
//
// The repo root is auto-detected as the directory containing go.mod
// at or above the current working directory.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulnertrack/kite-collector/tools/loginventory"
)

func main() {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "loginventory: %v\n", err)
		os.Exit(1)
	}
	body, err := loginventory.Generate(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loginventory: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "loginventory: write stdout: %v\n", err)
		os.Exit(1)
	}
}

// findRepoRoot walks up from CWD until it finds a directory containing
// go.mod. Returns an error if none is found before reaching the
// filesystem root.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	d := cwd
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("go.mod not found at or above %s", cwd)
		}
		d = parent
	}
}
