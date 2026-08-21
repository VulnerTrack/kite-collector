package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

// The exact failure from the field: ":8080" already owned by another
// process. The hint must name the override setting and how to find the
// current owner.
func TestAddrInUseHintNamesSettingAndPort(t *testing.T) {
	err := fmt.Errorf("listen tcp :8080: bind: %w", syscall.EADDRINUSE)
	attrs := addrInUseHint(err, ":8080", "api.addr / KITE_API_ADDR")
	if len(attrs) != 2 || attrs[0] != "hint" {
		t.Fatalf("attrs=%v", attrs)
	}
	hint, _ := attrs[1].(string)
	for _, must := range []string{"KITE_API_ADDR", "lsof -i :8080", "disables this listener"} {
		if !strings.Contains(hint, must) {
			t.Fatalf("hint missing %q: %s", must, hint)
		}
	}
}

// Windows surfaces WSAEADDRINUSE as text, not the unix errno — the
// text fallback must still recognise it.
func TestAddrInUseHintMatchesWindowsText(t *testing.T) {
	err := errors.New("listen tcp :8080: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if attrs := addrInUseHint(err, ":8080", "api.addr"); len(attrs) == 0 {
		t.Fatal("windows addr-in-use text must produce a hint")
	}
}

// Every other error stays hint-free so callers can append blindly.
func TestAddrInUseHintNilForOtherErrors(t *testing.T) {
	if attrs := addrInUseHint(errors.New("http: Server closed"), ":8080", "x"); attrs != nil {
		t.Fatalf("attrs=%v", attrs)
	}
	if attrs := addrInUseHint(nil, ":8080", "x"); attrs != nil {
		t.Fatalf("nil error must yield nil, got %v", attrs)
	}
}
