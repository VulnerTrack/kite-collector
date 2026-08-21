package main

import "strings"

// setupArgs is the parsed form of an installer-style command line (R13).
//
// Enterprise deployment tooling — SCCM, Intune, GPO startup scripts, Chocolatey
// wrappers — drives installers with the switch vocabulary Inno Setup and
// Windows Installer established two decades ago. RFC-0156 R13 exists so those
// operators do not have to fall back to the MSI channel just to get a silent
// install, so the switches are the ones they already type even though the
// implementation behind them is plain Go.
type setupArgs struct {
	InstallDir string
	LogPath    string
	Silent     bool
	VerySilent bool
	Help       bool
}

// setupUsage is printed for /? and /HELP.
func setupUsage() string {
	return strings.Join([]string{
		"kite-collector setup switches (unattended deployment):",
		"",
		"  /SILENT             install with no window and no prompts",
		"  /VERYSILENT         as /SILENT; also suppresses the completion notice",
		"  /DIR=\"<path>\"       install directory; must sit under %ProgramFiles%",
		"                      or %LOCALAPPDATA% (validated, traversal rejected)",
		"  /LOG=\"<path>\"       additional log destination (the install log is",
		"                      always written to %ProgramData%\\kite-collector)",
		"  /NORESTART          accepted and ignored — this installer never reboots",
		"  /SUPPRESSMSGBOXES   accepted and ignored — silent mode shows no dialogs",
		"  /?, /HELP           print this help",
		"",
		"Anything else is passed through to the normal CLI, e.g.:",
		"  kite-collector install --user",
		"",
	}, "\n")
}

// parseSetupArgs reports whether the command line is an installer invocation
// and, if so, what it asked for.
//
// The all-or-nothing rule matters: a command line is treated as setup switches
// only when *every* token is recognized. A partial match would swallow
// legitimate CLI invocations that happen to contain a slash-prefixed argument
// and route them into the installer, which on an elevated binary is a much
// worse failure than an unrecognized-flag error from cobra.
func parseSetupArgs(args []string) (setupArgs, bool) {
	var (
		parsed     setupArgs
		recognized bool
	)
	for _, raw := range args {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		name, value, hasValue := splitSetupToken(token)
		switch strings.ToUpper(name) {
		case "/SILENT", "--UNATTENDED":
			parsed.Silent = true
		case "/VERYSILENT":
			parsed.Silent = true
			parsed.VerySilent = true
		case "/DIR", "--INSTALL-DIR":
			if !hasValue || value == "" {
				return setupArgs{}, false
			}
			parsed.InstallDir = value
		case "/LOG":
			if !hasValue || value == "" {
				return setupArgs{}, false
			}
			parsed.LogPath = value
		case "/NORESTART", "/SUPPRESSMSGBOXES":
			// Accepted and ignored on purpose. Deployment tools append these
			// reflexively; rejecting them would fail perfectly good SCCM
			// packages over switches that describe behaviour this installer
			// already has (it never reboots, and silent mode has no dialogs).
		case "/?", "/HELP":
			parsed.Help = true
		default:
			return setupArgs{}, false
		}
		recognized = true
	}
	return parsed, recognized
}

// splitSetupToken splits "/DIR=C:\x" into ("/DIR", "C:\x", true) and "/SILENT"
// into ("/SILENT", "", false). Surrounding double quotes are stripped: cmd.exe
// usually removes them, PowerShell's argument passing sometimes does not, and
// an operator who typed /DIR="C:\Program Files\..." means the path, not the
// path-with-quotes.
func splitSetupToken(token string) (name, value string, hasValue bool) {
	idx := strings.Index(token, "=")
	if idx < 0 {
		return token, "", false
	}
	return token[:idx], strings.Trim(token[idx+1:], `"`), true
}
