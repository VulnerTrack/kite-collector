package driver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubCollector is a scriptable Collector for registry tests.
type stubCollector struct {
	err       error
	res       *Result
	name      string
	available bool
}

func (s *stubCollector) Name() string { return s.name }

func (s *stubCollector) Available() bool { return s.available }

func (s *stubCollector) Collect(context.Context) (*Result, error) { return s.res, s.err }

func TestNewRegistry_LoadsAllPlatformCollectors(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	require.Len(t, r.collectors, 7, "every platform collector must be pre-registered")

	names := make([]string, 0, len(r.collectors))
	for _, c := range r.collectors {
		names = append(names, c.Name())
	}
	assert.ElementsMatch(t, []string{
		"linux-procmodules",
		"linux-sysfs-bindings",
		"windows-wmi-drivers",
		"windows-pnputil",
		"darwin-kmutil-showloaded",
		"darwin-systemextensionsctl",
		"freebsd-kldstat",
	}, names)
}

func TestRegistry_RegisterAppends(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	extra := &stubCollector{name: "custom"}
	r.Register(extra)
	require.Len(t, r.collectors, 8)
	assert.Same(t, extra, r.collectors[7])
}

func TestRegistry_Collect_MergesSkipsAndRecordsFailures(t *testing.T) {
	t.Parallel()

	boom := errors.New("tool exploded")
	r := &Registry{collectors: []Collector{
		&stubCollector{
			name:      "ok-collector",
			available: true,
			res: &Result{
				Drivers: []LoadedDriver{{Name: "zeta"}, {Name: "alpha"}},
				Errs:    []CollectError{{Collector: "ok-collector", Line: 3}},
			},
		},
		&stubCollector{
			name:      "skipped-collector",
			available: false,
			res:       &Result{Drivers: []LoadedDriver{{Name: "never"}}},
		},
		&stubCollector{name: "failing-collector", available: true, err: boom},
		&stubCollector{name: "nil-result-collector", available: true, res: nil},
	}}

	res := r.Collect(context.Background())
	require.NotNil(t, res)

	require.Len(t, res.Drivers, 2, "unavailable and failing collectors contribute no drivers")
	assert.Equal(t, "alpha", res.Drivers[0].Name, "merged output must be sorted")
	assert.Equal(t, "zeta", res.Drivers[1].Name)

	require.Len(t, res.Errs, 2, "the parse error and the collector failure must both be recorded")
	var failure *CollectError
	for i := range res.Errs {
		if res.Errs[i].Collector == "failing-collector" {
			failure = &res.Errs[i]
		}
	}
	require.NotNil(t, failure, "a failing collector must be recorded under its name")
	assert.Same(t, boom, failure.Err)
}

func TestRegistry_Collect_NoAvailableCollectors(t *testing.T) {
	t.Parallel()

	r := &Registry{collectors: []Collector{
		&stubCollector{name: "off", available: false},
	}}
	res := r.Collect(context.Background())
	require.NotNil(t, res)
	assert.Empty(t, res.Drivers)
	assert.Empty(t, res.Bindings)
	assert.Empty(t, res.Errs)
}

// TestRegistry_Collect_ConcurrentMergeIsRaceFree stresses the concurrent
// merge path: many collectors complete in parallel and every driver must
// land exactly once in the sorted, merged result. Run with -race.
func TestRegistry_Collect_ConcurrentMergeIsRaceFree(t *testing.T) {
	t.Parallel()

	const collectors = 64
	const driversEach = 8

	r := &Registry{}
	for i := 0; i < collectors; i++ {
		res := &Result{}
		for j := 0; j < driversEach; j++ {
			res.Drivers = append(res.Drivers, LoadedDriver{
				Name: fmt.Sprintf("mod-%03d-%02d", i, j),
			})
		}
		r.Register(&stubCollector{
			name:      fmt.Sprintf("stub-%03d", i),
			available: true,
			res:       res,
		})
	}

	merged := r.Collect(context.Background())
	require.Len(t, merged.Drivers, collectors*driversEach,
		"every driver from every collector must appear exactly once")
	assert.Empty(t, merged.Errs)

	assert.True(t, sort.SliceIsSorted(merged.Drivers, func(i, j int) bool {
		return merged.Drivers[i].Name < merged.Drivers[j].Name
	}), "merged drivers must come out sorted by name")

	seen := make(map[string]struct{}, len(merged.Drivers))
	for _, d := range merged.Drivers {
		_, dup := seen[d.Name]
		require.False(t, dup, "duplicate driver %s in merged result", d.Name)
		seen[d.Name] = struct{}{}
	}
}
