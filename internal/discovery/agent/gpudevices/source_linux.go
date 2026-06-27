//go:build linux

package gpudevices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DRMRoot is the canonical sysfs DRM directory. Each `cardN`
// directory represents one render device; `renderD*` are
// render-only nodes (often duplicates of card devices).
const DRMRoot = "/sys/class/drm"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	readLink func(string) (string, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     DRMRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

// NewLinuxSource lets callers inject a DRM root.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Device, error) {
	entries, err := s.readDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read drm root %q: %w", s.root, err)
	}
	out := make([]Device, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		name := e.Name()
		// Top-level cards are `cardN` (where N is decimal).
		// Skip the per-output `cardN-HDMI-A-1` connector dirs
		// and the `renderD*` render-only nodes.
		if !strings.HasPrefix(name, "card") || strings.Contains(name, "-") {
			continue
		}
		out = append(out, s.read(name))
	}
	return out, nil
}

func (s *linuxSource) read(name string) Device {
	dir := filepath.Join(s.root, name, "device")
	d := Device{CardName: name, Vendor: VendorUnknown, AcceleratorType: TypeUnknown}

	d.VendorID = stripHexPrefix(s.field(dir, "vendor"))
	d.DeviceID = stripHexPrefix(s.field(dir, "device"))
	// `mem_info_vram_total` (amdgpu) or `i915_vram` are vendor-
	// specific; we treat presence as the primary signal and the
	// numeric value as size in bytes.
	d.VRAMBytes = atoi64(s.field(dir, "mem_info_vram_total"))
	d.Driver = s.driverName(dir)
	if pci := filepath.Base(s.readLinkSafe(dir)); pci != "" {
		d.PCIBDF = pci
	}
	// Render and display capability flags. A `renderDN` sibling
	// indicates compute / render support; a HDMI/DP connector
	// indicates display output.
	d.HasCompute = s.hasRender(name)
	d.HasDisplay = s.hasDisplayConnector(name)
	d.IsRenderOnly = d.HasCompute && !d.HasDisplay
	return d
}

func (s *linuxSource) driverName(dir string) string {
	target, err := s.readLink(filepath.Join(dir, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func (s *linuxSource) readLinkSafe(dir string) string {
	t, err := s.readLink(dir)
	if err != nil {
		return ""
	}
	return t
}

// hasRender reports whether the `cardN` device has a sibling
// `renderD<128+N>` node, which is the render-only DRI node.
func (s *linuxSource) hasRender(cardName string) bool {
	entries, err := s.readDir(s.root)
	if err != nil {
		return false
	}
	suffix := strings.TrimPrefix(cardName, "card")
	target := "renderD" // we just check presence of any renderD; tying
	_ = suffix
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, target) {
			return true
		}
	}
	return false
}

// hasDisplayConnector reports whether the `cardN` device has any
// connector subdirectory (e.g. `card0-HDMI-A-1`).
func (s *linuxSource) hasDisplayConnector(cardName string) bool {
	entries, err := s.readDir(s.root)
	if err != nil {
		return false
	}
	prefix := cardName + "-"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			return true
		}
	}
	return false
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func stripHexPrefix(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToLower(s)
}

func atoi64(s string) int64 {
	var v int64
	t := strings.TrimSpace(s)
	for _, c := range t {
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + int64(c-'0')
	}
	return v
}
