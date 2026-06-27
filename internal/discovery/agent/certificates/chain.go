package certificates

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured source collector and concatenates
// results. Per-source errors are logged at WARN and skipped — the
// PEM collector running fine shouldn't be blocked by an unimplementable
// Windows certstore call.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-source chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewPEMCollector(),
			NewMacOSKeychainCollector(),
			NewWindowsCertStoreCollector(),
		},
	}
}

func (chainCollector) Name() string { return "certificate-sources" }

func (c *chainCollector) Collect(ctx context.Context) ([]Certificate, error) {
	var out []Certificate
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("certificates: source collector failed",
				"source", sub.Name(), "error", err)
			continue
		}
		for _, cert := range got {
			if len(out) >= MaxCertificates {
				slog.Warn("certificates: cap reached, dropping later sources",
					"cap", MaxCertificates)
				SortCertificates(out)
				return out, nil
			}
			out = append(out, cert)
		}
	}
	SortCertificates(out)
	return out, nil
}
