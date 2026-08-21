package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
)

// addrInUseHint returns a `hint` log attribute when err is a bind
// failure caused by another process already owning the address —
// naming the setting that moves the listener (or disables it: empty
// addr means "off" for both the REST API and the dashboard) and the
// command that identifies the current owner. Returns nil for every
// other error so callers can append it unconditionally.
func addrInUseHint(err error, addr, setting string) []any {
	if !isAddrInUse(err) {
		return nil
	}
	return []any{"hint", fmt.Sprintf(
		"another process is already listening on %q — find it with `lsof -i %s` (unix) "+
			"or `netstat -ano` (windows), or point %s at a free port; "+
			"setting it empty disables this listener entirely",
		addr, portOf(addr), setting)}
}

// isAddrInUse recognises EADDRINUSE across platforms. Windows maps the
// condition to WSAEADDRINUSE, which errors.Is against the unix errno
// does not always match — the two text shapes cover the gap.
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "Only one usage of each socket address")
}

// portOf reduces a listen address to the ":port" form lsof expects.
func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return ":" + addr[i+1:]
	}
	return addr
}
