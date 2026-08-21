package driver

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectError_ErrorAndUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("expected numeric Id in column 1")
	ce := &CollectError{
		Err:       cause,
		Collector: "freebsd-kldstat",
		RawLine:   "garbage line",
		Line:      7,
	}

	assert.Equal(t,
		`freebsd-kldstat: line 7: expected numeric Id in column 1: "garbage line"`,
		ce.Error(),
		"Error() must render collector, line, cause, and quoted raw line")
	assert.Same(t, cause, ce.Unwrap())
	assert.ErrorIs(t, ce, cause, "errors.Is must see through Unwrap")
}

func TestResult_Merge_CombinesAndSorts(t *testing.T) {
	t.Parallel()

	dst := &Result{
		Drivers:  []LoadedDriver{{Name: "zz_late"}},
		Bindings: []DeviceBinding{{Bus: "usb", Address: "1-1"}},
		Errs:     []CollectError{{Collector: "a", Line: 1}},
	}
	src := &Result{
		Drivers:  []LoadedDriver{{Name: "aa_early"}},
		Bindings: []DeviceBinding{{Bus: "pci", Address: "0000:00:00.0"}},
		Errs:     []CollectError{{Collector: "b", Line: 2}},
	}

	dst.Merge(src)

	require.Len(t, dst.Drivers, 2)
	assert.Equal(t, "aa_early", dst.Drivers[0].Name, "merge must re-sort drivers by name")
	assert.Equal(t, "zz_late", dst.Drivers[1].Name)

	require.Len(t, dst.Bindings, 2)
	assert.Equal(t, "pci", dst.Bindings[0].Bus, "merge must re-sort bindings by bus")
	assert.Equal(t, "usb", dst.Bindings[1].Bus)

	require.Len(t, dst.Errs, 2)
	assert.Equal(t, "a", dst.Errs[0].Collector)
	assert.Equal(t, "b", dst.Errs[1].Collector)
}

func TestResult_Merge_NilOtherIsNoOp(t *testing.T) {
	t.Parallel()

	r := &Result{Drivers: []LoadedDriver{{Name: "keep"}}}
	r.Merge(nil)
	require.Len(t, r.Drivers, 1)
	assert.Equal(t, "keep", r.Drivers[0].Name)
}

func TestResult_Sort_TieBreakers(t *testing.T) {
	t.Parallel()

	r := &Result{
		Drivers: []LoadedDriver{
			{Name: "same", Version: "2.0"},
			{Name: "same", Version: "1.0"},
			{Name: "aaa", Version: "9.9"},
		},
		Bindings: []DeviceBinding{
			{Bus: "pci", Address: "0000:01:00.0"},
			{Bus: "pci", Address: "0000:00:1f.0"},
			{Bus: "usb", Address: "1-1"},
		},
	}
	r.Sort()

	assert.Equal(t, "aaa", r.Drivers[0].Name)
	assert.Equal(t, "1.0", r.Drivers[1].Version, "same-name drivers must sort by version")
	assert.Equal(t, "2.0", r.Drivers[2].Version)

	assert.Equal(t, "0000:00:1f.0", r.Bindings[0].Address, "same-bus bindings must sort by address")
	assert.Equal(t, "0000:01:00.0", r.Bindings[1].Address)
	assert.Equal(t, "usb", r.Bindings[2].Bus)
}

func TestResult_HasErrorsAndTotalErrors(t *testing.T) {
	t.Parallel()

	empty := &Result{}
	assert.False(t, empty.HasErrors())
	assert.Equal(t, 0, empty.TotalErrors())

	withErrs := &Result{Errs: []CollectError{{Line: 1}, {Line: 2}}}
	assert.True(t, withErrs.HasErrors())
	assert.Equal(t, 2, withErrs.TotalErrors())
}
