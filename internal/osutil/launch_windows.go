//go:build windows

package osutil

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcesses = kernel32.NewProc("GetConsoleProcessList") //#nosec G112 -- Windows API, not user input
)

// IsDoubleClicked reports whether the binary was launched by double-clicking
// in Windows Explorer. Detection uses GetConsoleProcessList: when launched
// from a terminal (cmd.exe, PowerShell) the console is shared with at least
// two processes; when double-clicked from Explorer the binary is the sole
// console owner.
func IsDoubleClicked() bool {
	if len(os.Args) > 1 {
		return false
	}
	var pids [4]uint32
	n, _, _ := procGetConsoleProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])), //#nosec G103 -- required for Windows syscall
		4,
	)
	// n <= 1 means we are the only process on this console → double-click.
	return n <= 1
}
