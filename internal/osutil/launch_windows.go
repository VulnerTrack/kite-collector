//go:build windows

package osutil

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// HideWindow configures the command so that no command prompt terminal window
// is created or flashed when executing it on Windows.
func HideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcesses = kernel32.NewProc("GetConsoleProcessList") //#nosec G112 -- Windows API, not user input
	procGetConsoleWindow    = kernel32.NewProc("GetConsoleWindow")
	procAttachConsole       = kernel32.NewProc("AttachConsole")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procShowWindow          = user32.NewProc("ShowWindow")
)

var attachedToConsole bool

// IsAttachedToConsole reports whether the process is attached to a parent console.
func IsAttachedToConsole() bool {
	return attachedToConsole
}

// HideConsole hides the console window of the current process on Windows.
func HideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		const SW_HIDE = 0
		_, _, _ = procShowWindow.Call(hwnd, SW_HIDE)
	}
}

// ShowConsole restores/shows the console window of the current process on Windows.
func ShowConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		const SW_SHOW = 5
		_, _, _ = procShowWindow.Call(hwnd, SW_SHOW)
	}
}

// redirectConsoleHandles redirects standard file descriptors to the attached console.
func redirectConsoleHandles() {
	if handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil && handle != syscall.InvalidHandle {
		os.Stdout = os.NewFile(uintptr(handle), "/dev/stdout")
	}
	if handle, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE); err == nil && handle != syscall.InvalidHandle {
		os.Stderr = os.NewFile(uintptr(handle), "/dev/stderr")
	}
	if handle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE); err == nil && handle != syscall.InvalidHandle {
		os.Stdin = os.NewFile(uintptr(handle), "/dev/stdin")
	}
}

// IsDoubleClicked reports whether the binary was launched by double-clicking
// in Windows Explorer. If launched from a terminal/console (e.g. cmd.exe, PowerShell),
// we attempt to attach to the parent console so CLI commands print output properly.
func IsDoubleClicked() bool {
	if len(os.Args) > 1 {
		// If there are arguments, it's definitely a CLI call.
		// Attach to the parent console if possible so output is visible.
		r, _, _ := procAttachConsole.Call(uintptr(0xffffffff))
		if r != 0 {
			attachedToConsole = true
			redirectConsoleHandles()
		}
		return false
	}

	// Attempt to attach to parent console (meaning we were run from a terminal command line).
	r, _, _ := procAttachConsole.Call(uintptr(0xffffffff))
	if r != 0 {
		attachedToConsole = true
		redirectConsoleHandles()
		return false
	}

	// Fallback to console process list detection
	var pids [4]uint32
	n, _, _ := procGetConsoleProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])), //#nosec G103 -- required for Windows syscall
		4,
	)
	// n <= 1 means we are the only process on this console → double-click.
	return n <= 1
}
