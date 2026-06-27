// Package osutil provides OS-aware helpers for CLI output and environment
// detection. All functions are safe for concurrent use.
package osutil

import (
	"fmt"
	"os"
	"runtime"
)

// EnvSetCommand returns the shell command to set an environment variable,
// adapted to the current operating system and shell.
//
//   - Linux/macOS: export KEY=VALUE
//   - Windows CMD: set KEY=VALUE
//   - Windows PowerShell: $env:KEY="VALUE"
func EnvSetCommand(key, value string) string {
	if runtime.GOOS == "windows" {
		if IsPowerShell() {
			return fmt.Sprintf(`$env:%s="%s"`, key, value)
		}
		return fmt.Sprintf(`set %s=%s`, key, value)
	}
	return fmt.Sprintf(`export %s=%s`, key, value)
}

// IsPowerShell returns true when the current process is running inside a
// PowerShell session. Detection is based on the PSModulePath environment
// variable which PowerShell always sets.
func IsPowerShell() bool {
	_, ok := os.LookupEnv("PSModulePath")
	return ok
}

// PathSeparator returns the OS-specific file path separator as a string.
func PathSeparator() string {
	if runtime.GOOS == "windows" {
		return `\`
	}
	return "/"
}

// ConfigDir returns the recommended configuration directory for kite-collector.
//
//   - Windows: %APPDATA%\kite-collector
//   - macOS:   ~/Library/Application Support/kite-collector
//   - Linux:   ~/.config/kite-collector (XDG)
func ConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return appdata + `\kite-collector`
		}
		return `C:\ProgramData\kite-collector`
	case "darwin":
		if home := os.Getenv("HOME"); home != "" {
			return home + "/Library/Application Support/kite-collector"
		}
		return "/tmp/kite-collector"
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg + "/kite-collector"
		}
		if home := os.Getenv("HOME"); home != "" {
			return home + "/.config/kite-collector"
		}
		return "/tmp/kite-collector"
	}
}

// ShellName returns a human-readable name for the likely active shell.
func ShellName() string {
	if runtime.GOOS == "windows" {
		if IsPowerShell() {
			return "PowerShell"
		}
		return "CMD"
	}
	if shell := os.Getenv("SHELL"); shell != "" {
		// Return just the basename.
		for i := len(shell) - 1; i >= 0; i-- {
			if shell[i] == '/' {
				return shell[i+1:]
			}
		}
		return shell
	}
	return "sh"
}
