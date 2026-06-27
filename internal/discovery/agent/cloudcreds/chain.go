package cloudcreds

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured source and concatenates results.
// Per-source errors are logged at WARN and skipped.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-provider chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewAWSCollector(),
			NewGCPCollector(),
			NewKubeconfigCollector(),
			NewAzureCollector(),
			NewGitHubCollector(),
			NewDockerCollector(),
			NewNPMCollector(),
			NewTerraformCloudCollector(),
		},
	}
}

func (chainCollector) Name() string { return "cloud-credentials" }

func (c *chainCollector) Collect(ctx context.Context) ([]Credential, error) {
	var out []Credential
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("cloudcreds: source collector failed",
				"source", sub.Name(), "error", err)
			continue
		}
		for _, c := range got {
			if len(out) >= MaxCredentials {
				slog.Warn("cloudcreds: cap reached, dropping later sources",
					"cap", MaxCredentials)
				SortCredentials(out)
				return out, nil
			}
			out = append(out, c)
		}
	}
	SortCredentials(out)
	return out, nil
}
