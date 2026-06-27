package intranetweb

import (
	"context"
	"fmt"
	"sync"
)

// activeCollector probes every target the resolver returns. The probe
// is the only side-effectful step — and even then it's GET / with a
// short timeout, no auth, no body. The package doc explains why
// InsecureSkipVerify is acceptable here.
type activeCollector struct {
	resolver TargetResolver
	probe    HTTPProbe
	// MaxConcurrency caps the number of in-flight probes. LAN sweeps
	// are typically fast, but appliances with slow web stacks (printers,
	// PDU UIs) can sit on a connection for the full timeout. The default
	// 16 keeps the sweep parallel without storming a single small LAN.
	maxConcurrency int
}

// NewCollector wires together the default resolver chain (hosts file
// only — LAN discovery feeds get plumbed in by the parent agent) and
// a default probe configuration.
func NewCollector() Collector {
	return &activeCollector{
		resolver:       NewHostsFileResolver(),
		probe:          HTTPProbe{},
		maxConcurrency: 16,
	}
}

// NewCollectorWith lets the agent wire its own resolver (typically a
// ChainResolver folding in the LAN-discovery output) and override the
// concurrency budget.
func NewCollectorWith(resolver TargetResolver, probe HTTPProbe, concurrency int) Collector {
	if concurrency <= 0 {
		concurrency = 16
	}
	return &activeCollector{
		resolver:       resolver,
		probe:          probe,
		maxConcurrency: concurrency,
	}
}

func (c *activeCollector) Name() string { return "intranet-web-active" }

func (c *activeCollector) Collect(ctx context.Context) ([]Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	targets, err := c.resolver.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, nil
	}

	sem := make(chan struct{}, c.maxConcurrency)
	results := make(chan Endpoint, len(targets))
	var wg sync.WaitGroup

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		t := t // capture loop var (Go 1.22+ no-ops but keeps the intent obvious)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			scheme := pickScheme(t.Port)
			ep, err := c.probe.Probe(ctx, scheme, t)
			if err == nil {
				results <- ep
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]Endpoint, 0, len(targets))
	for ep := range results {
		out = append(out, ep)
		if len(out) >= MaxEndpoints {
			// Drain remaining sends to let goroutines finish.
			go func() {
				for range results {
				}
			}()
			break
		}
	}
	SortEndpoints(out)
	return out, nil
}

// pickScheme decides whether to probe http or https first based on
// port convention. Ambiguous ports (3000, 5000, etc.) get probed as
// http because almost every dev framework defaults to plain.
func pickScheme(port int) Scheme {
	if IsTLSPort(port) {
		return SchemeHTTPS
	}
	return SchemeHTTP
}
