package storage

import (
	"net"
	"strings"
)

// snippetLimit caps the length of Match.Snippet so log lines stay short
// even when a multi-megabyte JS bundle triggers a regex match.
const snippetLimit = 160

// Detect runs every catalogue signature against the supplied evidence and
// returns the resulting matches. The function is pure: no I/O, no goroutines,
// no global state writes.
//
// Behaviour notes:
//
//   - A single Evidence can yield multiple Match values when several
//     signatures fire. Duplicates (same Provider + Signal + Reason) are
//     suppressed so a caller iterating a megabyte JS file doesn't end up
//     with hundreds of identical entries.
//   - Empty Evidence fields are skipped silently — the detector does not
//     treat absence as a no-match.
//   - The function never returns an error; an invalid CIDR in the catalogue
//     would be caught by tests, not callers.
func Detect(ev Evidence) []Match {
	return DetectWith(catalogue, ev)
}

// DetectWith is the catalogue-injectable form of Detect. It is exported so
// tests (and downstream consumers building custom rule sets) can supply
// their own signature list without monkeypatching the package-level
// catalogue.
func DetectWith(sigs []Signature, ev Evidence) []Match {
	matches := make([]Match, 0)
	seen := make(map[string]struct{})

	add := func(m Match) {
		key := string(m.Provider) + "|" + string(m.Signal) + "|" + m.Reason
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		matches = append(matches, m)
	}

	for i, sig := range sigs {
		switch sig.Signal {
		case SignalFile:
			if m, ok := matchFile(sig, ev, i); ok {
				add(m)
			}
		case SignalTLS:
			if m, ok := matchTLS(sig, ev, i); ok {
				add(m)
			}
		case SignalJA4:
			if m, ok := matchLiteral(sig, ev.JA4, i); ok {
				add(m)
			}
		case SignalJA4S:
			if m, ok := matchLiteral(sig, ev.JA4S, i); ok {
				add(m)
			}
		case SignalJA4H:
			if m, ok := matchLiteral(sig, ev.JA4H, i); ok {
				add(m)
			}
		case SignalJA5:
			if m, ok := matchLiteral(sig, ev.JA5, i); ok {
				add(m)
			}
		case SignalAPI:
			if api := matchAPI(sig, ev, i); len(api) > 0 {
				for _, m := range api {
					add(m)
				}
			}
		case SignalNetwork:
			if m, ok := matchNetwork(sig, ev, i); ok {
				add(m)
			}
		case SignalBucket:
			if m, ok := matchBucket(sig, ev, i); ok {
				add(m)
			}
		}
	}

	return matches
}

// matchFile applies a SignalFile signature against the filename, URL, and JS
// source. The first non-empty field that matches produces the result.
func matchFile(sig Signature, ev Evidence, id int) (Match, bool) {
	candidates := []string{ev.Filename, ev.URL, ev.JS}
	for _, text := range candidates {
		if text == "" {
			continue
		}
		if m, ok := firstHit(sig, text, id); ok {
			return m, true
		}
	}
	return Match{}, false
}

// matchTLS checks SNI and SAN entries against the signature's pattern.
// Literal SAN matches are also supported via Signature.Literals (lower-cased
// equality).
func matchTLS(sig Signature, ev Evidence, id int) (Match, bool) {
	candidates := append([]string{ev.TLSServerName}, ev.TLSSANs...)
	for _, name := range candidates {
		if name == "" {
			continue
		}
		if m, ok := firstHit(sig, name, id); ok {
			return m, true
		}
	}
	return Match{}, false
}

// matchAPI runs the signature against (a) every HTTP header name+value pair
// and (b) the URL string and JS source. API rules typically target headers
// like x-amz-request-id but also catch endpoint paths embedded in JS.
func matchAPI(sig Signature, ev Evidence, id int) []Match {
	var out []Match

	for name, vals := range ev.APIHeaders {
		line := strings.ToLower(name) + ": " + strings.Join(vals, ",")
		if m, ok := firstHit(sig, line, id); ok {
			out = append(out, m)
		}
	}

	for _, text := range []string{ev.URL, ev.JS} {
		if text == "" {
			continue
		}
		if m, ok := firstHit(sig, text, id); ok {
			out = append(out, m)
		}
	}
	return out
}

// matchNetwork tests Evidence.RemoteIP against the signature's CIDR list.
// Invalid CIDR entries are silently skipped; this defends production callers
// from a malformed catalogue addition.
func matchNetwork(sig Signature, ev Evidence, id int) (Match, bool) {
	if ev.RemoteIP == "" {
		return Match{}, false
	}
	ip := net.ParseIP(ev.RemoteIP)
	if ip == nil {
		return Match{}, false
	}
	for _, cidr := range sig.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return makeMatch(sig, id, ev.RemoteIP+" ∈ "+cidr), true
		}
	}
	return Match{}, false
}

// matchBucket runs the signature pattern against BucketHost, URL, and
// DNSChain entries. The matched fragment becomes the Match snippet so
// downstream code can capture the bucket name.
func matchBucket(sig Signature, ev Evidence, id int) (Match, bool) {
	candidates := []string{ev.BucketHost, ev.URL}
	candidates = append(candidates, ev.DNSChain...)
	for _, text := range candidates {
		if text == "" {
			continue
		}
		if m, ok := firstHit(sig, text, id); ok {
			return m, true
		}
	}
	return Match{}, false
}

// matchLiteral does case-sensitive equality on a fingerprint hash field.
// This is used for JA4, JA4S, JA4H, JA5 — those values are canonical hex
// digests where casing matters and substrings would be wrong.
func matchLiteral(sig Signature, value string, id int) (Match, bool) {
	if value == "" {
		return Match{}, false
	}
	for _, lit := range sig.Literals {
		if lit == value {
			return makeMatch(sig, id, value), true
		}
	}
	return Match{}, false
}

// firstHit tries Pattern then Literals against text. Literals are matched
// case-insensitively via strings.Contains — they target JS substrings
// ("supabase.storage.from") and header names where casing is unreliable.
func firstHit(sig Signature, text string, id int) (Match, bool) {
	if sig.Pattern != nil {
		if loc := sig.Pattern.FindStringIndex(text); loc != nil {
			return makeMatch(sig, id, snippet(text, loc[0], loc[1])), true
		}
	}
	lc := strings.ToLower(text)
	for _, lit := range sig.Literals {
		if lit == "" {
			continue
		}
		if idx := strings.Index(lc, strings.ToLower(lit)); idx >= 0 {
			return makeMatch(sig, id, snippet(text, idx, idx+len(lit))), true
		}
	}
	return Match{}, false
}

// snippet returns a truncated excerpt of text around [start, end].
func snippet(text string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	excerpt := text[start:end]
	if len(excerpt) > snippetLimit {
		excerpt = excerpt[:snippetLimit] + "…"
	}
	return excerpt
}

// makeMatch fills a Match value from a signature plus the snippet that
// triggered it. The signature index is preserved so callers can correlate a
// match back to the catalogue entry for debugging.
func makeMatch(sig Signature, id int, snip string) Match {
	return Match{
		Provider:    sig.Provider,
		Signal:      sig.Signal,
		Reason:      sig.Description,
		Snippet:     snip,
		Confidence:  sig.Confidence,
		SignatureID: id,
	}
}
