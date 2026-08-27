//go:build windows

package secretstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// dpapiStore uses Windows DPAPI in CurrentUser scope. A collector installed as
// LocalSystem therefore binds its credentials to that service identity and
// this machine. The password itself is sent to PowerShell through stdin, never
// through the process command line.
type dpapiStore struct{ dir string }

func newNativeStore() *dpapiStore {
	root := os.Getenv("ProgramData")
	if root == "" {
		return nil
	}
	return &dpapiStore{dir: filepath.Join(root, "VulnerTrack", "Kite", "secrets")}
}
func (s *dpapiStore) Backend() string { return "windows-dpapi-current-user" }
func (s *dpapiStore) Available() bool {
	_, err := exec.LookPath("powershell.exe")
	return err == nil
}
func (s *dpapiStore) path(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".dpapi")
}
func (s *dpapiStore) Put(name string, value []byte) error {
	path := s.path(name)
	if err := ensurePrivateDir(path); err != nil {
		return err
	}
	script := `$v=[Console]::In.ReadToEnd();$b=[Text.Encoding]::UTF8.GetBytes($v);$p=[Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);[IO.File]::WriteAllBytes($args[0],$p)`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, path) // #nosec G204 -- path is generated internally.
	cmd.Stdin = bytes.NewReader(value)
	return cmd.Run()
}
func (s *dpapiStore) Get(name string) ([]byte, error) {
	path := s.path(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	script := `$p=[IO.File]::ReadAllBytes($args[0]);$b=[Security.Cryptography.ProtectedData]::Unprotect($p,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);[Console]::Out.Write([Text.Encoding]::UTF8.GetString($b))`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, path).Output() // #nosec G204
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil, ErrNotFound
	}
	return out, nil
}
func (s *dpapiStore) Delete(name string) error {
	err := os.Remove(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
