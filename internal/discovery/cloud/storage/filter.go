package storage

// Filter narrows a Match slice by provider, signal type, and minimum
// confidence. Zero-valued fields are treated as "no constraint" so callers
// can combine constraints without scaffolding (e.g. Filter{MinConfidence:
// ConfidenceHigh}.Apply(matches) keeps only HIGH bands).
type Filter struct {
	Providers      []Provider
	Signals        []SignalType
	MinConfidence  Confidence
	ExcludeSignals []SignalType
}

// Apply returns the subset of matches that satisfy every populated
// constraint. The original slice is not modified.
func (f Filter) Apply(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	providerSet := toSet(f.Providers, func(p Provider) string { return string(p) })
	signalSet := toSet(f.Signals, func(s SignalType) string { return string(s) })
	excludeSet := toSet(f.ExcludeSignals, func(s SignalType) string { return string(s) })

	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		if len(providerSet) > 0 {
			if _, ok := providerSet[string(m.Provider)]; !ok {
				continue
			}
		}
		if len(signalSet) > 0 {
			if _, ok := signalSet[string(m.Signal)]; !ok {
				continue
			}
		}
		if _, blocked := excludeSet[string(m.Signal)]; blocked {
			continue
		}
		if f.MinConfidence > 0 && m.Confidence < f.MinConfidence {
			continue
		}
		out = append(out, m)
	}
	return out
}

// toSet builds a set keyed by a stringer projection. The generic-ish
// signature avoids importing constraints just for this helper.
func toSet[T any](items []T, key func(T) string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[key(item)] = struct{}{}
	}
	return out
}

// GroupByProvider buckets matches by their Provider. Useful for emitting one
// summary line per detected backend rather than per signature hit.
func GroupByProvider(matches []Match) map[Provider][]Match {
	out := make(map[Provider][]Match)
	for _, m := range matches {
		out[m.Provider] = append(out[m.Provider], m)
	}
	return out
}
