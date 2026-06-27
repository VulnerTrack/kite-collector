package kernelmod

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseProcModules walks the /proc/modules format. Each non-empty
// line has the shape:
//
//	name size refcount used_by_csv state load_address [taints]
//
// `used_by_csv` is `-` when no other module depends on this one,
// otherwise a comma-separated list with a trailing comma. The
// optional taints field is a parenthesised letter sequence like
// `(OE)`. We tolerate kernels that don't expose `load_address`
// (the column is replaced with `(no instrumentation)` text on
// CONFIG_KALLSYMS=n kernels).
func ParseProcModules(raw []byte) []Module {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	// /proc/modules lines can hold long used_by lists; bump the buffer.
	scan.Buffer(make([]byte, 0, 4096), 1<<20)

	out := make([]Module, 0, 64)
	for scan.Scan() {
		line := strings.TrimRight(scan.Text(), "\n\r")
		if line == "" {
			continue
		}
		m, ok := parseProcModulesLine(line)
		if !ok {
			continue
		}
		out = append(out, m)
		if len(out) >= MaxModules {
			break
		}
	}
	return out
}

// parseProcModulesLine handles one /proc/modules row.
func parseProcModulesLine(line string) (Module, bool) {
	// Fields() is fine here — /proc/modules uses single-space
	// separators and never quotes anything.
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Module{}, false
	}

	m := Module{
		Name:   fields[0],
		Source: SourceLinuxProcModules,
		State:  StateUnknown,
	}

	if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
		m.SizeBytes = n
	}
	if n, err := strconv.Atoi(fields[2]); err == nil {
		m.Refcount = n
	}

	// used_by: "-" → none; otherwise "modA,modB," with trailing comma.
	if fields[3] != "-" {
		raw := strings.TrimRight(fields[3], ",")
		for _, u := range strings.Split(raw, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				m.UsedBy = append(m.UsedBy, u)
			}
		}
	}

	if len(fields) >= 5 {
		m.State = normalizeState(fields[4])
	}

	// fields[5] = load_address or "(no instrumentation)".
	if len(fields) >= 6 && strings.HasPrefix(fields[5], "0x") {
		m.LoadAddress = fields[5]
	}

	// Optional trailing taint, e.g. "(OE)".
	if last := fields[len(fields)-1]; strings.HasPrefix(last, "(") &&
		strings.HasSuffix(last, ")") && last != "(no" {
		m.Taints = strings.Trim(last, "()")
	}

	m.IsTainting = HasTaintingFlag(m.Taints)
	// /proc/modules itself never exposes the file path; the linux
	// collector populates FilePath + IsOutOfTree by walking /sys.
	return m, true
}

func normalizeState(s string) State {
	switch strings.ToLower(s) {
	case "live":
		return StateLive
	case "loading":
		return StateLoading
	case "unloading":
		return StateUnloading
	}
	return StateUnknown
}

// MergeSysfs enriches the in-memory module list with per-module
// data the caller harvested from /sys/module/<name>/. The expected
// `sysfs` map keys are module names and the values carry whatever
// the sysfs walker could read: file path, version, signer, taints
// (which override the /proc/modules taints when present).
func MergeSysfs(mods []Module, sysfs map[string]SysfsExtras) []Module {
	for i := range mods {
		extra, ok := sysfs[mods[i].Name]
		if !ok {
			continue
		}
		if extra.FilePath != "" {
			mods[i].FilePath = extra.FilePath
			mods[i].IsOutOfTree = IsOutOfTreePath(extra.FilePath)
		}
		if extra.Version != "" {
			mods[i].Version = extra.Version
		}
		if extra.Signer != "" {
			mods[i].Signer = extra.Signer
			mods[i].IsUnsigned = false
		} else if extra.SignatureChecked {
			mods[i].IsUnsigned = true
		}
		if extra.Taints != "" {
			mods[i].Taints = extra.Taints
			mods[i].IsTainting = HasTaintingFlag(extra.Taints)
		}
		if extra.FileHash != "" {
			mods[i].FileHash = extra.FileHash
		}
	}
	return mods
}

// SysfsExtras carries the per-module data the Linux collector reads
// from /sys/module/<name>/ (or computes from the resolved .ko file).
// `SignatureChecked=true` with an empty `Signer` means the collector
// looked and found no signature — that's how IsUnsigned is set.
type SysfsExtras struct {
	FilePath         string
	FileHash         string
	Version          string
	Signer           string
	Taints           string
	SignatureChecked bool
}
