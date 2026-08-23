package dashboard

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"sort"
)

// Facets on the curated tabs (machines, software, containers).
//
// The generic /tables/{name} view already carries a facet rail, computed by
// the store's FacetTable over the whole table. The curated tabs render a
// hand-picked, joined projection instead of a raw table, so they can't reuse
// that path: there is no single table to facet, and the displayed columns
// (a machine's IP label, a software row's host) don't exist as store columns.
//
// Instead these facets are computed in Go from the rows the page already
// loaded, and the filter is applied to those same rows. Two consequences,
// both intended:
//
//   - Counts match exactly what the grid shows (the page caps at 500 rows;
//     the facet reflects that same set, not a larger table behind it).
//   - Clicking a value filters the curated page IN PLACE — the row set
//     narrows but the curated columns stay — rather than bouncing to the
//     generic grid.

// pageFacetColumn is one candidate facet column: a name and the value it
// takes on each row, index-aligned with the page's row slice.
type pageFacetColumn struct {
	Name   string
	Values []string
}

// pageFacetValue is one selectable bucket within a facet card.
type pageFacetValue struct {
	Value    string
	Count    int
	Selected bool
}

// pageFacet is one facet card: a low-cardinality column and its top values.
type pageFacet struct {
	Column   string
	Distinct int
	Values   []pageFacetValue
}

// buildPageFacets projects the candidate columns onto facet cards, mirroring
// the store's FacetTable rules: a column becomes a card only when its distinct
// value count is at most maxDistinct, and each card lists at most topN values
// ordered by count (desc) then value (asc, for stability). filterCol/filterVal
// mark the active selection so the rail can render it as selected.
//
// Facets are computed over the UNFILTERED rows so every value stays visible
// with its full count while the grid narrows — the same behaviour the generic
// rail has, where selecting a value never hides the others.
func buildPageFacets(cols []pageFacetColumn, maxDistinct, topN int, filterCol, filterVal string, filtered bool) []pageFacet {
	out := make([]pageFacet, 0, len(cols))
	for _, col := range cols {
		counts := make(map[string]int, len(col.Values))
		for _, v := range col.Values {
			counts[v]++
		}
		if len(counts) == 0 || len(counts) > maxDistinct {
			// Empty (nothing to facet) or too high-cardinality to be useful.
			continue
		}
		values := make([]pageFacetValue, 0, len(counts))
		for v, c := range counts {
			values = append(values, pageFacetValue{
				Value:    v,
				Count:    c,
				Selected: filtered && filterCol == col.Name && filterVal == v,
			})
		}
		sort.Slice(values, func(i, j int) bool {
			if values[i].Count != values[j].Count {
				return values[i].Count > values[j].Count
			}
			return values[i].Value < values[j].Value
		})
		distinct := len(values)
		if len(values) > topN {
			values = values[:topN]
		}
		out = append(out, pageFacet{Column: col.Name, Distinct: distinct, Values: values})
	}
	// Stable card order so the rail doesn't reshuffle between renders.
	sort.Slice(out, func(i, j int) bool { return out[i].Column < out[j].Column })
	return out
}

// pageFacetKeep returns the indices of the rows that survive the active
// filter. When no filter is active (or the selected column isn't among the
// candidates) it returns nil, meaning "keep every row" — the caller treats a
// nil mask as the identity so the unfiltered path stays allocation-free.
func pageFacetKeep(cols []pageFacetColumn, filterCol, filterVal string, filtered bool) []int {
	if !filtered {
		return nil
	}
	var col *pageFacetColumn
	for i := range cols {
		if cols[i].Name == filterCol {
			col = &cols[i]
			break
		}
	}
	if col == nil {
		return nil
	}
	keep := make([]int, 0, len(col.Values))
	for i, v := range col.Values {
		if v == filterVal {
			keep = append(keep, i)
		}
	}
	return keep
}

// pickByIndex returns the rows at the given indices, preserving order. It is
// the companion to pageFacetKeep: keep := pageFacetKeep(...); rows =
// pickByIndex(rows, keep) narrows a curated slice to the facet selection. A
// nil idx means "no filter" and returns the slice unchanged.
func pickByIndex[T any](rows []T, idx []int) []T {
	if idx == nil {
		return rows
	}
	out := make([]T, 0, len(idx))
	for _, i := range idx {
		if i >= 0 && i < len(rows) {
			out = append(out, rows[i])
		}
	}
	return out
}

// facetRailView is the data the standalone rail template renders. BasePath is
// the URL the facet links post back to (e.g. "/machines"), so the curated
// page keeps its own address instead of the generic /tables one.
type facetRailView struct {
	BasePath  string
	Facets    []pageFacet
	Filtered  bool
	FilterCol string
	FilterVal string
	Shown     int
	Total     int
}

// renderFacetRail renders the rail to an HTML fragment the curated templates
// embed via {{.FacetRail}}. It returns an empty fragment (not an error) when
// there is nothing to facet, so a page with no low-cardinality columns simply
// shows no rail.
func renderFacetRail(v facetRailView) (template.HTML, error) {
	if len(v.Facets) == 0 && !v.Filtered {
		return "", nil
	}
	var buf bytes.Buffer
	if err := facetRailTmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("render facet rail: %w", err)
	}
	// #nosec G203 -- every dynamic value below is emitted through html/template
	// auto-escaping or url.QueryEscape; the assembled fragment is trusted.
	return template.HTML(buf.String()), nil
}

// facetQS builds the "?fcol=..&fval=.." query string for a facet link, with
// both parts escaped. Exposed to the template as a function so link
// construction lives in one place.
func facetQS(col, val string) template.URL {
	// #nosec G203 -- parts are QueryEscape'd, so the result is inert.
	return template.URL("?fcol=" + url.QueryEscape(col) + "&fval=" + url.QueryEscape(val))
}

var facetRailTmpl = template.Must(
	template.New("facet-rail").
		Funcs(template.FuncMap{"facetQS": facetQS}).
		Parse(facetRailTemplate))

// facetRailTemplate mirrors the facet rail baked into tableTemplate, but is
// standalone and parametrised by BasePath so the curated tabs can filter in
// place. Keep the class names in sync with the generic rail — they share the
// stylesheet.
const facetRailTemplate = `
{{if .Filtered}}
<div class="facet-active-chip">
  Filtered by <code>{{.FilterCol}}</code> = <code>{{if .FilterVal}}{{.FilterVal}}{{else}}(empty){{end}}</code>
  <span class="muted small">&mdash; {{.Shown}} of {{.Total}} rows</span>
  <a class="btn btn-ghost btn-sm" href="{{.BasePath}}" hx-get="{{.BasePath}}" hx-target="#content" hx-push-url="true">Clear</a>
</div>
{{end}}
{{if .Facets}}
<div class="facet-rail">
  <div class="facet-rail-head">Facets <span class="muted small">columns with at most 20 distinct values &mdash; select a value to filter in place</span></div>
  <div class="facet-cards">
  {{$root := .}}
  {{range .Facets}}
    {{$col := .Column}}
    <div class="facet-card">
      <div class="facet-card-head"><code>{{.Column}}</code><span class="muted small">{{.Distinct}} values</span></div>
      {{range .Values}}
      {{if .Selected}}
      <a class="facet-row facet-selected" href="{{$root.BasePath}}" hx-get="{{$root.BasePath}}" hx-target="#content" hx-push-url="true" title="Clear filter">
        <span class="facet-value">{{if .Value}}{{.Value}}{{else}}&mdash; empty{{end}}</span><span class="facet-count">{{.Count}} &times;</span>
      </a>
      {{else}}
      <a class="facet-row" href="{{$root.BasePath}}{{facetQS $col .Value}}" hx-get="{{$root.BasePath}}{{facetQS $col .Value}}" hx-target="#content" hx-push-url="true">
        <span class="facet-value">{{if .Value}}{{.Value}}{{else}}&mdash; empty{{end}}</span><span class="facet-count">{{.Count}}</span>
      </a>
      {{end}}
      {{end}}
    </div>
  {{end}}
  </div>
</div>
{{end}}
`
