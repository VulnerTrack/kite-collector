package apifingerprint

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"sync"
)

// Target is the input to ScanTargets. The orchestrator builds one
// Target per (open TCP port, HTTP-ish scheme) pair — for example, an
// open 443 yields one Target with Scheme="https"; an open 8080 typically
// yields one with Scheme="http". For ambiguous ports, GuessSchemes can
// produce both ("http" and "https") so we don't miss TLS-fronted
// services on unusual ports.
type Target struct {
	Host   string
	Scheme string
	Port   int
}

// URL returns the canonical base URL for the target, suitable for
// passing into Detector.Probe.
func (t Target) URL() (*url.URL, error) {
	if t.Host == "" {
		return nil, fmt.Errorf("apifingerprint: empty host")
	}
	if t.Port <= 0 || t.Port > 65535 {
		return nil, fmt.Errorf("apifingerprint: invalid port %d", t.Port)
	}
	scheme := t.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("apifingerprint: unsupported scheme %q", scheme)
	}
	hostport := t.Host + ":" + strconv.Itoa(t.Port)
	return &url.URL{Scheme: scheme, Host: hostport}, nil
}

// ScanOptions controls the parallel sweep. Zero values are sane:
// MaxConcurrent defaults to 4 (small enough not to saturate a target,
// large enough to overlap RTTs across distinct hosts).
type ScanOptions struct {
	MaxConcurrent int
}

// ScanTargets sweeps detector across every target in parallel, bounded
// by opts.MaxConcurrent, and returns one Result per target — including
// targets that produced zero fingerprints, so callers can tell "we
// scanned and found nothing" apart from "we never looked".
//
// Targets are scanned concurrently; results are returned in a stable
// order (sorted by host then port then scheme) regardless of which
// finished first, so downstream JSON / hash output is deterministic.
//
// ctx cancellation aborts any in-flight probes and short-circuits the
// remaining queue; the partial result slice is still returned.
func ScanTargets(ctx context.Context, d *Detector, targets []Target, opts ScanOptions) ([]Result, error) {
	if d == nil {
		return nil, fmt.Errorf("apifingerprint: nil detector")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	maxC := opts.MaxConcurrent
	if maxC <= 0 {
		maxC = 4
	}
	if maxC > len(targets) {
		maxC = len(targets)
	}

	out := make([]Result, len(targets))
	hadErr := make([]error, len(targets))

	sem := make(chan struct{}, maxC)
	var wg sync.WaitGroup
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return sortedResults(out), fmt.Errorf("apifingerprint: ctx cancelled before dispatch: %w", err)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			u, err := t.URL()
			if err != nil {
				hadErr[idx] = err
				return
			}
			res, err := d.Probe(ctx, u)
			if err != nil {
				hadErr[idx] = err
			}
			out[idx] = res
		}(i, t)
	}
	wg.Wait()

	sorted := sortedResults(out)
	// Surface the first non-nil error; partial results stay in `sorted`.
	for _, e := range hadErr {
		if e != nil {
			return sorted, e
		}
	}
	return sorted, nil
}

// sortedResults returns a copy of out filtered to entries that actually
// scanned (Endpoint set) and ordered by endpoint string. This is the
// canonical output ordering used by downstream consumers.
func sortedResults(out []Result) []Result {
	sorted := make([]Result, 0, len(out))
	for _, r := range out {
		if r.Endpoint == "" {
			continue
		}
		sorted = append(sorted, r)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Endpoint < sorted[j].Endpoint
	})
	return sorted
}

// GuessSchemes returns the URL schemes a TCP scanner should try when
// it observes an open port without further context. The defaults reflect
// observed reality on the open internet, not the IANA registry:
//
//   - well-known TLS ports (443, 8443, 4443, 9443, 8843) → "https"
//   - common cleartext HTTP ports (80, 8000, 8008, 8080, 8888, 3000,
//     5000, 9000, 9090, 7000, 7070, 7474, 7777, 8081, 8085, 8086,
//     8181, 8200, 8300, 8500, 8800) → "http"
//   - ports that are routinely fronted with TLS in modern stacks
//     (10000, 15672, 25672, 9200, 5601) → both
//   - everything else → both (cheap; the path cache short-circuits the
//     wasted second round-trip)
func GuessSchemes(port int) []string {
	switch port {
	case 443, 4443, 8443, 9443, 8843:
		return []string{"https"}
	case 80, 8000, 8008, 8080, 8081, 8085, 8086, 8181, 8888,
		3000, 5000, 7000, 7070, 7474, 7777,
		9000, 9090, 9091, 9292,
		8200, 8300, 8500, 8800:
		return []string{"http"}
	}
	return []string{"http", "https"}
}

// TargetsFromHostPorts builds one Target per (host, port, scheme)
// combination using GuessSchemes to decide which schemes to try.
// Convenience helper for orchestrators converting a TCP scan output
// to apifingerprint input.
func TargetsFromHostPorts(host string, ports []int) []Target {
	if host == "" || len(ports) == 0 {
		return nil
	}
	out := make([]Target, 0, len(ports))
	for _, p := range ports {
		for _, scheme := range GuessSchemes(p) {
			out = append(out, Target{Host: host, Port: p, Scheme: scheme})
		}
	}
	return out
}
