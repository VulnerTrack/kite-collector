//go:build linux

package sensors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HwmonRoot is the canonical sysfs hwmon directory.
const HwmonRoot = "/sys/class/hwmon"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     HwmonRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

// NewLinuxSource lets callers inject an hwmon root.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

// channelKinds maps the hwmon channel-name prefix to its sensor
// type. Each prefix's input file ends with `_input` and may have
// `_max`, `_crit`, `_label` siblings.
var channelKinds = []struct {
	prefix string
	typ    SensorType
}{
	{"temp", SensorTemp},
	{"fan", SensorFan},
	{"in", SensorVoltage},
	{"curr", SensorCurrent},
	{"power", SensorPower},
	{"energy", SensorEnergy},
	{"humidity", SensorHumidity},
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Sensor, error) {
	hwmons, err := s.readDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read hwmon root %q: %w", s.root, err)
	}

	var out []Sensor
	for _, h := range hwmons {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		hdir := filepath.Join(s.root, h.Name())
		chip := strings.TrimSpace(s.field(hdir, "name"))
		entries, err := s.readDir(hdir)
		if err != nil {
			continue
		}
		for _, ck := range channelKinds {
			indices := collectChannelIndices(entries, ck.prefix)
			for _, idx := range indices {
				s.appendChannel(&out, hdir, chip, ck, idx)
			}
		}
	}
	return out, nil
}

func (s *linuxSource) appendChannel(out *[]Sensor, hdir, chip string, ck struct {
	prefix string
	typ    SensorType
}, idx int,
) {
	name := fmt.Sprintf("%s%d", ck.prefix, idx)
	raw := strings.TrimSpace(s.field(hdir, name+"_input"))
	if raw == "" {
		return
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return
	}
	sn := Sensor{
		Chip:        chip,
		SensorName:  name,
		SensorLabel: strings.TrimSpace(s.field(hdir, name+"_label")),
		SensorType:  ck.typ,
		ValueMillis: v,
	}
	if mx, err := strconv.ParseInt(strings.TrimSpace(s.field(hdir, name+"_max")), 10, 64); err == nil {
		sn.MaxMillis = mx
	}
	if cr, err := strconv.ParseInt(strings.TrimSpace(s.field(hdir, name+"_crit")), 10, 64); err == nil {
		sn.CritMillis = cr
	}
	*out = append(*out, sn)
}

// collectChannelIndices scans hwmon entry names for the form
// `<prefix><index>_input` and returns the sorted set of indices.
func collectChannelIndices(entries []os.DirEntry, prefix string) []int {
	seen := map[int]struct{}{}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, "_input") {
			continue
		}
		mid := strings.TrimSuffix(strings.TrimPrefix(n, prefix), "_input")
		v, err := strconv.Atoi(mid)
		if err != nil {
			continue
		}
		seen[v] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Deterministic.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}
