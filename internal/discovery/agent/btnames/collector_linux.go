//go:build linux

package btnames

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultBlueZRoot is the canonical BlueZ device-cache root. Some
// non-systemd distros use `/var/lib/bluez/` — collectors override
// via the constructor.
const DefaultBlueZRoot = "/var/lib/bluetooth"

// fileCollector walks the BlueZ cache and parses per-device info.
type fileCollector struct {
	now      func() time.Time
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	getenv   func(string) string
	roots    []string
}

// NewCollector returns a Collector wired to canonical BlueZ paths.
func NewCollector() Collector {
	return &fileCollector{
		roots:    []string{DefaultBlueZRoot, "/var/lib/bluez"},
		now:      time.Now,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		getenv:   os.Getenv,
	}
}

func (c *fileCollector) Name() string { return "btnames-bluez" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.roots...)
	if p := c.getenv("BTNAMES_BLUEZ_ROOT"); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, root := range roots {
		c.scanAdapter(root, &out)
		if len(out) >= MaxRows {
			break
		}
	}
	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortRows(out)
	return out, nil
}

// scanAdapter looks for adapter MAC dirs under the BlueZ root and
// recurses one level into per-device dirs.
func (c *fileCollector) scanAdapter(root string, out *[]Row) {
	entries, err := c.readDir(root)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !IsValidMAC(e.Name()) {
			continue
		}
		adapter := e.Name()
		adapterDir := filepath.Join(root, adapter)
		devEntries, err := c.readDir(adapterDir)
		if err != nil {
			continue
		}
		sort.Slice(devEntries, func(i, j int) bool { return devEntries[i].Name() < devEntries[j].Name() })
		for _, d := range devEntries {
			if !d.IsDir() {
				continue
			}
			if !IsValidMAC(d.Name()) {
				continue
			}
			info := filepath.Join(adapterDir, d.Name(), "info")
			c.consider(info, adapter, d.Name(), out)
			if len(*out) >= MaxRows {
				return
			}
		}
	}
}

// consider parses a single per-device info file and emits a Row.
func (c *fileCollector) consider(path, adapter, device string, out *[]Row) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	info := ParseBlueZInfo(body)
	name := info.Alias
	if name == "" {
		name = info.Name
	}
	if name == "" {
		// No name recorded; skip — there's nothing useful for the
		// hostname-discovery pipeline.
		return
	}
	row := Row{
		CollectedAt:    c.now().UTC().Format(time.RFC3339),
		Source:         SourceLinuxBlueZ,
		AdapterMAC:     adapter,
		DeviceMAC:      device,
		DeviceName:     name,
		DeviceNameHash: HashName(name),
		Manufacturer:   info.Manufacturer,
		DeviceClass:    info.DeviceClass,
		IsBLE:          info.IsBLE,
		IsTrusted:      info.IsTrusted,
		IsBlocked:      info.IsBlocked,
		IsConnected:    info.IsConnected,
		SourcePath:     path,
	}
	if row.DeviceClass == "" {
		row.DeviceClass = DeviceClassUnknown
	}
	if fi, err := c.statFile(path); err == nil {
		row.LastSeen = fi.ModTime().UTC().Format(time.RFC3339)
		if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
			row.IsLastSeenRecent = true
		}
	}
	*out = append(*out, row)
}
