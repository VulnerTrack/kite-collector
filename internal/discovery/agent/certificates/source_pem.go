package certificates

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// pemCollector walks the standard Unix trust-store directories and
// classifies each cert. The same logical cert can appear under multiple
// filenames (Debian uses both Common Name and OpenSSL subject hash) —
// dedup happens at the Collect level via the sha256 fingerprint.
//
// Default scan paths (operator can override via cfg in a future iter):
//
//	/etc/ssl/certs            — Debian/Ubuntu/Arch system roots (symlinks)
//	/usr/local/share/ca-certificates — Debian/Ubuntu admin-installed
//	/etc/pki/ca-trust/source/anchors — RHEL/Fedora admin-installed
//	/etc/pki/tls/certs        — RHEL/Fedora system roots
//	/etc/pki/ca-trust/extracted/pem  — RHEL/Fedora extracted bundle
//
// Bundle files (ca-bundle.crt, ca-certificates.crt) are parsed as
// multi-PEM concatenations; single .pem/.crt files are parsed as one.
type pemCollector struct {
	readFile func(string) ([]byte, error)
	walkDir  func(string, fs.WalkDirFunc) error
	roots    []pemRoot
}

// pemRoot pairs a scan directory with the Store it implies.
type pemRoot struct {
	path  string
	store Store
}

// NewPEMCollector returns the default Unix trust-store walker.
func NewPEMCollector() Collector {
	return &pemCollector{
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths only
		walkDir:  filepath.WalkDir,
		roots: []pemRoot{
			{"/etc/ssl/certs", StoreSystemRoot},
			{"/usr/local/share/ca-certificates", StoreSystemRoot},
			{"/etc/pki/ca-trust/source/anchors", StoreSystemRoot},
			{"/etc/pki/ca-trust/extracted/pem", StoreSystemRoot},
			{"/etc/pki/tls/certs", StoreSystemRoot},
		},
	}
}

func (c *pemCollector) Name() string { return "pem-files" }

func (c *pemCollector) Collect(ctx context.Context) ([]Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	seen := make(map[string]bool, 256) // by fingerprint within (store, fingerprint) tuple
	var out []Certificate

	for _, root := range c.roots {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		walkErr := c.walkDir(root.path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// EACCES / ENOENT on a single entry shouldn't abort the walk.
				return nil //nolint:nilerr // intentional: skip unreadable entries
			}
			if d.IsDir() {
				return nil
			}
			if !looksLikeCertFile(path) {
				return nil
			}
			data, rerr := c.readFile(path)
			if rerr != nil {
				slog.Debug("certificates: read failed", "path", path, "error", rerr)
				return nil
			}
			for _, x := range ParsePEMBundle(data) {
				cert := FromX509(x, root.store, path)
				key := string(root.store) + "|" + cert.FingerprintSHA256
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, cert)
				if len(out) >= MaxCertificates {
					return filepath.SkipAll
				}
			}
			return nil
		})
		if walkErr != nil && !isMissingErr(walkErr) && !errors.Is(walkErr, filepath.SkipAll) {
			slog.Debug("certificates: walk error", "root", root.path, "error", walkErr)
		}
	}
	SortCertificates(out)
	return out, nil
}

// looksLikeCertFile returns true for filenames a PEM walker should open.
// Includes the unusual `.0`-suffix files (OpenSSL subject-hash symlinks
// in /etc/ssl/certs on older distros).
func looksLikeCertFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(name, ".pem"),
		strings.HasSuffix(name, ".crt"),
		strings.HasSuffix(name, ".cer"),
		name == "ca-bundle.crt",
		name == "ca-certificates.crt",
		name == "tls-ca-bundle.pem":
		return true
	}
	// OpenSSL subject-hash symlinks: 8 hex chars + `.0`/`.1`/`.2`...
	if i := strings.LastIndexByte(name, '.'); i == 8 {
		base := name[:8]
		ext := name[9:]
		if isHex(base) && len(ext) >= 1 && ext[0] >= '0' && ext[0] <= '9' {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func isMissingErr(err error) bool {
	return err != nil && (os.IsNotExist(err) || strings.Contains(err.Error(), "no such file"))
}
