package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeTaintBits_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		want  []string
		value uint64
	}{
		{"clean kernel", []string{}, 0},
		{"P proprietary", []string{"P"}, 1 << 0},
		{"F force loaded", []string{"F"}, 1 << 1},
		{"S out-of-spec", []string{"S"}, 1 << 2},
		{"R force unloaded", []string{"R"}, 1 << 3},
		{"M MCE", []string{"M"}, 1 << 4},
		{"B bad page", []string{"B"}, 1 << 5},
		{"U userspace tainted", []string{"U"}, 1 << 6},
		{"D died (OOPS)", []string{"D"}, 1 << 7},
		{"A ACPI override", []string{"A"}, 1 << 8},
		{"W warning", []string{"W"}, 1 << 9},
		{"C staging driver", []string{"C"}, 1 << 10},
		{"I firmware workaround", []string{"I"}, 1 << 11},
		{"O out-of-tree", []string{"O"}, 1 << 12},
		{"E unsigned module", []string{"E"}, 1 << 13},
		{"L soft lockup", []string{"L"}, 1 << 14},
		{"K live patched", []string{"K"}, 1 << 15},
		{"X auxiliary", []string{"X"}, 1 << 16},
		{"T struct randomization", []string{"T"}, 1 << 17},
		{"N in-kernel test", []string{"N"}, 1 << 18},
		{"O+E nvidia + unsigned", []string{"E", "O"}, (1 << 12) | (1 << 13)},
		{"P+O+E proprietary out-of-tree unsigned", []string{"E", "O", "P"}, (1 << 0) | (1 << 12) | (1 << 13)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, DecodeTaintBits(tc.value))
		})
	}
}

func TestParseTaintValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  uint64
	}{
		{"0\n", 0},
		{"4096\n", 4096},
		{"  12288 \n", 12288},
		{"", 0},
		{"not-a-number", 0},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, parseTaintValue(tc.input), tc.input)
	}
}

func TestReadKernelTaint_NoFileReturnsNil(t *testing.T) {
	// On Windows/macOS test runners /proc/sys/kernel/tainted is absent;
	// the helper must degrade to nil and not panic.
	got := ReadKernelTaint()
	if got == nil {
		return
	}
	for _, code := range got {
		assert.Contains(t, []string{"P", "F", "S", "R", "M", "B", "U", "D", "A", "W", "C", "I", "O", "E", "L", "K", "X", "T", "N"}, code)
	}
}
