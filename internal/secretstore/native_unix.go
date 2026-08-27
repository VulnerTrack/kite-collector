//go:build !windows

package secretstore

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type commandStore struct{ kind string }

func newNativeStore() *commandStore {
	switch runtime.GOOS {
	case "darwin":
		return &commandStore{kind: "macos-keychain"}
	case "linux":
		return &commandStore{kind: "linux-secret-service"}
	default:
		return nil
	}
}

func (s *commandStore) Backend() string { return s.kind }
func (s *commandStore) Available() bool {
	if s.kind == "macos-keychain" {
		_, err := exec.LookPath("security")
		return err == nil
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return false
	}
	_, err := exec.LookPath("secret-tool")
	return err == nil
}
func (s *commandStore) Put(name string, value []byte) error {
	var cmd *exec.Cmd
	if s.kind == "macos-keychain" {
		cmd = exec.Command("security", "add-generic-password", "-U", "-s", "com.vulnertrack.kite", "-a", name, "-w", string(value)) // #nosec G204 -- fixed executable and arguments.
	} else {
		cmd = exec.Command("secret-tool", "store", "--label=Kite collector integration", "application", "kite-collector", "name", name) // #nosec G204
		cmd.Stdin = bytes.NewReader(value)
	}
	return cmd.Run()
}
func (s *commandStore) Get(name string) ([]byte, error) {
	var cmd *exec.Cmd
	if s.kind == "macos-keychain" {
		cmd = exec.Command("security", "find-generic-password", "-s", "com.vulnertrack.kite", "-a", name, "-w") // #nosec G204
	} else {
		cmd = exec.Command("secret-tool", "lookup", "application", "kite-collector", "name", name) // #nosec G204
	}
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil, ErrNotFound
	}
	return bytes.TrimSpace(out), nil
}
func (s *commandStore) Delete(name string) error {
	var cmd *exec.Cmd
	if s.kind == "macos-keychain" {
		cmd = exec.Command("security", "delete-generic-password", "-s", "com.vulnertrack.kite", "-a", name) // #nosec G204
	} else {
		cmd = exec.Command("secret-tool", "clear", "application", "kite-collector", "name", name) // #nosec G204
	}
	err := cmd.Run()
	if err != nil && !errors.Is(err, exec.ErrNotFound) {
		return err
	}
	return nil
}
