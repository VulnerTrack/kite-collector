//go:build windows

package osutil

import (
	"syscall"
	"unsafe"
)

// Two distinct Windows-console behaviours have to be opted into before our
// CLI output renders correctly:
//
//  1. Codepage. Legacy PowerShell / cmd.exe default the console codepage to
//     OEM-437 (or the OEM CP for the locale), which mangles UTF-8 byte
//     sequences. We set both input and output codepages to 65001 (UTF-8).
//
//  2. Virtual terminal processing. ConHost treats ESC bytes (0x1B) as
//     printable by default — ANSI/VT escape sequences emitted by our banner
//     (24-bit truecolor for the Vulnertrack wordmark) come through as raw
//     "+[1;38;2;…m" text instead of styling. ENABLE_VIRTUAL_TERMINAL_PROCESSING
//     (0x0004) on the STD_OUTPUT and STD_ERROR handles flips that behaviour.
//
// Modern Windows Terminal and PowerShell 7+ already have both flags on; this
// init is a no-op there. The codepage is per-console-session so the kernel
// restores the previous value when our process exits — no cleanup needed.
//
// Failures (redirected streams, legacy Server Core, missing console) are
// intentionally silent: the worst case is the pre-fix rendering, which the
// operator can still work around with `chcp 65001` + a modern terminal.

const (
	cpUTF8                          = 65001
	enableVirtualTerminalProcessing = 0x0004
)

var (
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
)

// init runs before main() because osutil is imported by cmd/kite-collector.
// kernel32 is declared in launch_windows.go (same package + build tag).
func init() {
	_, _, _ = procSetConsoleOutputCP.Call(uintptr(cpUTF8))
	_, _, _ = procSetConsoleCP.Call(uintptr(cpUTF8))
	enableVTOn(syscall.Stdout)
	enableVTOn(syscall.Stderr)
}

// enableVTOn flips ENABLE_VIRTUAL_TERMINAL_PROCESSING on the given std
// handle while preserving every other mode bit. Read-modify-write because
// SetConsoleMode replaces the entire mode flags, not merges.
func enableVTOn(h syscall.Handle) {
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))) //#nosec G103 -- required for Windows console API
	if ret == 0 {
		// Not a console (handle was redirected to a file/pipe) — nothing to do.
		return
	}
	_, _, _ = procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
}
