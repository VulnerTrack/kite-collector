package sshkeys

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// fileCollector walks every user's ~/.ssh directory plus the system
// /etc/ssh tree, classifies each file by name, and parses out keys.
// On Linux/BSDs/macOS the agent typically runs as a service so we don't
// know which user is "the user" — we walk every entry under /home,
// /Users, or C:\Users (mirrors the browser/editor extension collectors).
type fileCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	etcSSH    string
	homeRoots []string
}

// NewCollector returns the default file-walker SSH-key collector.
func NewCollector() Collector {
	return &fileCollector{
		homeRoots: defaultHomeRoots(),
		etcSSH:    "/etc/ssh",
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME and /etc/ssh paths only
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "ssh-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Key

	// Walk per-user ~/.ssh.
	for _, root := range c.homeRoots {
		users, err := c.readDir(root)
		if err != nil {
			continue
		}
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			if isSystemUserName(u.Name()) {
				continue
			}
			sshDir := filepath.Join(root, u.Name(), ".ssh")
			out = append(out, c.collectUserSSH(ctx, u.Name(), sshDir)...)
			if len(out) >= MaxKeys {
				SortKeys(out)
				return out[:MaxKeys], nil
			}
		}
	}

	// System host keys + the optional /etc/ssh/ssh_known_hosts trust list.
	out = append(out, c.collectSystemSSH(ctx)...)
	if len(out) > MaxKeys {
		out = out[:MaxKeys]
	}
	SortKeys(out)
	return out, nil
}

// collectUserSSH classifies and parses every recognised file under one
// user's ~/.ssh directory. Unreadable individual files are logged and
// skipped — most often EACCES on the agent's unprivileged scan.
func (c *fileCollector) collectUserSSH(ctx context.Context, user, sshDir string) []Key {
	entries, err := c.readDir(sshDir)
	if err != nil {
		return nil
	}
	var out []Key
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out
		}
		if e.IsDir() {
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		name := e.Name()

		switch {
		case name == "authorized_keys", name == "authorized_keys2":
			out = append(out, c.parseAuthorized(path, user)...)
		case name == "known_hosts":
			out = append(out, c.parseKnown(path, user, RoleKnownHost)...)
		case strings.HasSuffix(name, ".pub") && strings.HasPrefix(name, "id_"):
			out = append(out, c.parseIdentityPublic(path, user)...)
		case strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub"):
			out = append(out, c.parseIdentityPrivate(path, user)...)
		}
	}
	return out
}

// collectSystemSSH pulls /etc/ssh/ssh_host_*_key.pub (host keys we
// present to inbound clients) + /etc/ssh/ssh_known_hosts (system-wide
// trust list, if present).
func (c *fileCollector) collectSystemSSH(_ context.Context) []Key {
	entries, err := c.readDir(c.etcSSH)
	if err != nil {
		return nil
	}
	var out []Key
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(c.etcSSH, name)
		switch {
		case strings.HasPrefix(name, "ssh_host_") && strings.HasSuffix(name, "_key.pub"):
			out = append(out, c.parseIdentityFileAs(path, "", RoleHostKey)...)
		case name == "ssh_known_hosts":
			out = append(out, c.parseKnown(path, "", RoleKnownHost)...)
		}
	}
	return out
}

// parseAuthorized reads ~/.ssh/authorized_keys and emits one Key per
// non-comment line. options + comment are preserved per row.
func (c *fileCollector) parseAuthorized(path, owner string) []Key {
	data, err := c.readFile(path)
	if err != nil {
		slog.Debug("sshkeys: authorized_keys read failed",
			"path", path, "error", err)
		return nil
	}
	var out []Key
	for i, raw := range strings.Split(string(data), "\n") {
		kt, _, comment, options, blob, ok := ParseAuthorizedKeysLine(raw)
		if !ok {
			continue
		}
		sha, md := FingerprintBlob(blob)
		bits := KeyBitsFromBlob(blob)
		out = append(out, Key{
			Role:              RoleAuthorized,
			OwnerUser:         owner,
			KeyType:           kt,
			KeyBits:           bits,
			FingerprintSHA256: sha,
			FingerprintMD5:    md,
			Comment:           comment,
			Options:           options,
			SourcePath:        path,
			LineNo:            i + 1,
			IsWeak:            IsWeakKeyType(kt, bits),
		})
	}
	return out
}

// parseKnown handles both ~/.ssh/known_hosts and /etc/ssh/ssh_known_hosts.
func (c *fileCollector) parseKnown(path, owner string, role Role) []Key {
	data, err := c.readFile(path)
	if err != nil {
		slog.Debug("sshkeys: known_hosts read failed",
			"path", path, "error", err)
		return nil
	}
	var out []Key
	for i, raw := range strings.Split(string(data), "\n") {
		host, kt, _, comment, blob, ok := ParseKnownHostsLine(raw)
		if !ok {
			continue
		}
		sha, md := FingerprintBlob(blob)
		bits := KeyBitsFromBlob(blob)
		out = append(out, Key{
			Role:              role,
			OwnerUser:         owner,
			KeyType:           kt,
			KeyBits:           bits,
			FingerprintSHA256: sha,
			FingerprintMD5:    md,
			Comment:           comment,
			Hostname:          host,
			SourcePath:        path,
			LineNo:            i + 1,
			IsWeak:            IsWeakKeyType(kt, bits),
		})
	}
	return out
}

// parseIdentityPublic parses a `~/.ssh/id_*.pub` file: single-line
// public key in authorized_keys format (no options).
func (c *fileCollector) parseIdentityPublic(path, owner string) []Key {
	return c.parseIdentityFileAs(path, owner, RoleIdentityPublic)
}

func (c *fileCollector) parseIdentityFileAs(path, owner string, role Role) []Key {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(data))
	kt, _, comment, _, blob, ok := ParseAuthorizedKeysLine(line)
	if !ok {
		return nil
	}
	sha, md := FingerprintBlob(blob)
	bits := KeyBitsFromBlob(blob)
	return []Key{{
		Role:              role,
		OwnerUser:         owner,
		KeyType:           kt,
		KeyBits:           bits,
		FingerprintSHA256: sha,
		FingerprintMD5:    md,
		Comment:           comment,
		SourcePath:        path,
		IsWeak:            IsWeakKeyType(kt, bits),
	}}
}

// parseIdentityPrivate emits a row for an `~/.ssh/id_*` private key
// without consuming the secret material — we never log or store key
// bytes. We DO inspect the PEM body to detect passphrase protection
// (PrivateKeyHasPassphrase), but only the boolean result lands in the
// row. The fingerprint column is left empty when no companion .pub
// file resolves it (the public key isn't recoverable from an encrypted
// private key without the passphrase).
func (c *fileCollector) parseIdentityPrivate(path, owner string) []Key {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	has, recognised := PrivateKeyHasPassphrase(data)
	if !recognised {
		// Not an SSH private key (might be config, ed25519 cert, etc.)
		return nil
	}
	// Try to find a companion .pub to lift the fingerprint + key_type.
	companion := path + ".pub"
	pubData, _ := c.readFile(companion)
	kt := ""
	bits := 0
	sha := ""
	md := ""
	if line := strings.TrimSpace(string(pubData)); line != "" {
		if k, _, _, _, blob, ok := ParseAuthorizedKeysLine(line); ok {
			kt = k
			sha, md = FingerprintBlob(blob)
			bits = KeyBitsFromBlob(blob)
		}
	}
	if sha == "" {
		// Synthesise a stable fingerprint from the path so the unique-
		// index in SQLite doesn't collide across multiple unrecognised
		// keys. This is intentionally NOT cryptographic.
		sha = "no-companion-pub:" + path
	}
	return []Key{{
		Role:              RoleIdentityPrivate,
		OwnerUser:         owner,
		KeyType:           kt,
		KeyBits:           bits,
		FingerprintSHA256: sha,
		FingerprintMD5:    md,
		HasPassphrase:     has,
		SourcePath:        path,
		IsWeak:            IsWeakKeyType(kt, bits),
	}}
}

// defaultHomeRoots returns the per-OS directories whose immediate
// subdirectories are user homes.
func defaultHomeRoots() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		return []string{"/home", "/root"}
	case "darwin":
		return []string{"/Users", "/var/root"}
	case "windows":
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users`}
	}
	return nil
}

func isSystemUserName(name string) bool {
	switch strings.ToLower(name) {
	case "shared", "guest", "public", "default", "all users",
		"defaultappuser", "defaultaccount", "wdagutilityaccount":
		return true
	}
	return false
}
