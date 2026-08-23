package dashboard

import (
	"context"
	"net/url"
	"os"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// containerFilter is the facet selection carried through the containers page.
// It rides the poll and toggle URLs so an auto-refresh (or pausing) keeps the
// active filter instead of snapping back to the full list.
type containerFilter struct {
	Col string
	Val string
	On  bool
}

// containerFilterFromRequestValues builds the filter from parsed fcol/fval.
func newContainerFilter(col, val string, on bool) containerFilter {
	return containerFilter{Col: col, Val: val, On: on}
}

// apply appends the filter's fcol/fval to a URL so a link preserves it. A
// no-op when the filter is off.
func (f containerFilter) apply(u string) string {
	if !f.On {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + "fcol=" + url.QueryEscape(f.Col) + "&fval=" + url.QueryEscape(f.Val)
}

// resolveLocalAsset finds the asset record for the host this dashboard runs
// on, so the containers page can show whether the machine those containers run
// on is an authorized, managed asset. All live containers share one host, so
// this is page-level context rather than a per-row column.
//
// Best-effort: with no store, no match, or a lookup error it returns known=false
// and the page simply omits the status.
func resolveLocalAsset(ctx context.Context, st store.Store) (m model.Machine, known bool) {
	if st == nil {
		return model.Machine{}, false
	}
	machines, err := st.ListMachines(ctx, store.MachineFilter{Limit: 5000})
	if err != nil {
		return model.Machine{}, false
	}
	hostname := ""
	if h, herr := os.Hostname(); herr == nil {
		hostname = strings.TrimSpace(h)
	}
	// Prefer an exact hostname match; fall back to the row the local agent
	// wrote for itself.
	var fallback *model.Machine
	for i := range machines {
		if hostname != "" && strings.EqualFold(strings.TrimSpace(machines[i].Hostname), hostname) {
			return machines[i], true
		}
		src := strings.ToLower(strings.TrimSpace(machines[i].DiscoverySource))
		if fallback == nil && (src == "local_controller" || src == "agent") {
			fallback = &machines[i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return model.Machine{}, false
}
