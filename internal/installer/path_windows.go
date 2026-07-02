//go:build windows

package installer

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ConfigurePath adds the binary directory to the Windows PATH registry key if not already present.
func ConfigurePath(opts Options) error {
	var (
		k   registry.Key
		err error
	)

	binaryDir := filepath.Clean(opts.BinaryDir)

	if opts.UserMode {
		k, err = registry.OpenKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE|registry.SET_VALUE)
	} else {
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	}
	if err != nil {
		return err
	}
	defer k.Close()

	pathVal, valType, err := k.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return err
	}

	// Split current path elements
	elements := filepath.SplitList(pathVal)
	alreadyExists := false
	for _, elem := range elements {
		if strings.EqualFold(filepath.Clean(elem), binaryDir) {
			alreadyExists = true
			break
		}
	}

	if !alreadyExists {
		// Append the new directory
		newPathVal := pathVal
		if len(newPathVal) > 0 && !strings.HasSuffix(newPathVal, ";") {
			newPathVal += ";"
		}
		newPathVal += binaryDir

		// Write back using the same value type
		if valType == registry.EXPAND_SZ {
			err = k.SetExpandStringValue("Path", newPathVal)
		} else {
			err = k.SetStringValue("Path", newPathVal)
		}
		if err != nil {
			return err
		}

		// Broadcast environment change to the system
		notifyEnvironmentChange()
	}

	return nil
}

func notifyEnvironmentChange() {
	const (
		WM_SETTINGCHANGE = 0x001A
		HWND_BROADCAST   = 0xFFFF
		SMTO_ABORTIFHUNG = 0x0002
	)

	user32 := windows.NewLazySystemDLL("user32.dll")
	procSendMessageTimeoutW := user32.NewProc("SendMessageTimeoutW")

	envStr, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}

	var result uintptr
	_, _, _ = procSendMessageTimeoutW.Call(
		uintptr(HWND_BROADCAST),
		uintptr(WM_SETTINGCHANGE),
		0,
		uintptr(unsafe.Pointer(envStr)),
		uintptr(SMTO_ABORTIFHUNG),
		5000,
		uintptr(unsafe.Pointer(&result)),
	)
}
