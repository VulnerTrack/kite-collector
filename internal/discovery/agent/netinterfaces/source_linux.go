//go:build linux

package netinterfaces

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SysfsRoot is the canonical sysfs net-interface directory.
const SysfsRoot = "/sys/class/net"

// Flag bits in /sys/class/net/<iface>/flags (read as hex).
const (
	IFFPromisc = 0x100 // IFF_PROMISC
)

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	readLink func(string) (string, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

// NewLinuxSource lets callers inject a sysfs root.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Iface, error) {
	entries, err := s.readDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read net root %q: %w", s.root, err)
	}
	out := make([]Iface, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		out = append(out, s.read(e.Name()))
	}
	return out, nil
}

func (s *linuxSource) read(name string) Iface {
	dir := filepath.Join(s.root, name)
	i := Iface{Iface: name, Operstate: OpUnknown}
	i.SetRawMAC(strings.TrimSpace(s.field(dir, "address")))
	i.Operstate = parseOperstate(strings.TrimSpace(s.field(dir, "operstate")))
	i.Carrier = strings.TrimSpace(s.field(dir, "carrier")) == "1"
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(dir, "mtu"))); err == nil {
		i.MTU = v
	}
	// `speed` is unreadable on virtual ifaces (returns -1 or error).
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(dir, "speed"))); err == nil && v > 0 {
		i.SpeedMbps = v
	}
	i.Duplex = parseDuplex(strings.TrimSpace(s.field(dir, "duplex")))
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(dir, "tx_queue_len"))); err == nil {
		i.TxQueueLen = v
	}
	// flags is hex.
	if v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(s.field(dir, "flags")), "0x"), 16, 32); err == nil {
		if v&IFFPromisc != 0 {
			i.IsPromiscuous = true
		}
	}
	i.Driver = s.driverName(dir)
	if pci := s.pciBDF(dir); pci != "" {
		i.PCIBDF = pci
	}
	return i
}

func (s *linuxSource) driverName(dir string) string {
	target, err := s.readLink(filepath.Join(dir, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// pciBDF returns the PCI BDF the interface's parent device sits
// on (or "" for non-PCI ifaces).
func (s *linuxSource) pciBDF(dir string) string {
	target, err := s.readLink(filepath.Join(dir, "device"))
	if err != nil {
		return ""
	}
	base := filepath.Base(target)
	if isBDF(base) {
		return base
	}
	return ""
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}

func parseOperstate(s string) Operstate {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up":
		return OpUp
	case "down":
		return OpDown
	case "dormant":
		return OpDormant
	case "testing":
		return OpTesting
	case "lowerlayerdown":
		return OpLowerLayerDown
	case "notpresent":
		return OpNotPresent
	}
	return OpUnknown
}

func parseDuplex(s string) Duplex {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "full":
		return DuplexFull
	case "half":
		return DuplexHalf
	case "":
		return DuplexNone
	}
	return DuplexUnknown
}

// isBDF reports whether name matches dddd:bb:dd.f canonical form.
func isBDF(name string) bool {
	if len(name) != 12 {
		return false
	}
	if name[4] != ':' || name[7] != ':' || name[10] != '.' {
		return false
	}
	for i, c := range name {
		switch i {
		case 4, 7, 10:
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
