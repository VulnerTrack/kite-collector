package driver

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// TaintBit maps a kernel taint bit position to its single-letter code as
// documented by docs.kernel.org/admin-guide/tainted-kernels.html.
type TaintBit struct {
	Letter string
	Reason string
}

// taintBits is the canonical bit table from the upstream kernel docs.
// Order is bit position (0-indexed). Codes G/N for bit 0 are by convention
// — only the negative form ('P' for proprietary) is recorded; absence
// implies the GPL/clean state.
var taintBits = map[int]TaintBit{
	0:  {"P", "proprietary module loaded"},
	1:  {"F", "module force loaded"},
	2:  {"S", "kernel running on out-of-spec system"},
	3:  {"R", "module force unloaded"},
	4:  {"M", "processor reported a Machine Check Exception"},
	5:  {"B", "bad page referenced or some unexpected page flags"},
	6:  {"U", "taint requested by userspace"},
	7:  {"D", "kernel died recently (OOPS or BUG)"},
	8:  {"A", "ACPI table overridden"},
	9:  {"W", "warning issued by the kernel"},
	10: {"C", "staging driver loaded"},
	11: {"I", "workaround for serious bug in platform firmware applied"},
	12: {"O", "externally-built (out-of-tree) module loaded"},
	13: {"E", "unsigned module was loaded"},
	14: {"L", "soft lockup occurred"},
	15: {"K", "kernel has been live patched"},
	16: {"X", "auxiliary taint, defined for and used by distros"},
	17: {"T", "kernel was built with the struct randomization plugin"},
	18: {"N", "an in-kernel test has been run"},
}

// DecodeTaintBits converts a 64-bit taint value into the sorted list of
// single-letter codes per the kernel doc.
func DecodeTaintBits(value uint64) []string {
	out := []string{}
	for bit, t := range taintBits {
		if value&(1<<bit) != 0 {
			out = append(out, t.Letter)
		}
	}
	sort.Strings(out)
	return out
}

// ReadKernelTaint reads /proc/sys/kernel/tainted and decodes its contents.
// Returns an empty slice when the file is missing or cannot be parsed.
func ReadKernelTaint() []string {
	raw, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return nil
	}
	return DecodeTaintBits(parseTaintValue(string(raw)))
}

func parseTaintValue(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
