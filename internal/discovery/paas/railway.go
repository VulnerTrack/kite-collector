package paas

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

const railwayProjectsQuery = `query {
  me {
    projects {
      edges {
        node {
          id
          name
          services {
            edges {
              node {
                id
                name
                icon
              }
            }
          }
          environments {
            edges {
              node {
                id
                name
              }
            }
          }
        }
      }
    }
  }
}`

// Railway implements discovery.Source for the Railway GraphQL API.
type Railway struct {
	baseURL string
}

// NewRailway returns a new Railway discovery source.
func NewRailway() *Railway {
	return &Railway{baseURL: "https://backboard.railway.com"}
}

// Name returns the stable identifier for this source.
func (ry *Railway) Name() string { return "railway" }

// Discover lists all Railway projects and their services via GraphQL.
// Credentials: KITE_RAILWAY_TOKEN environment variable.
func (ry *Railway) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_RAILWAY_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("railway: KITE_RAILWAY_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("railway: starting discovery")

	client := newClient("railway", ry.baseURL, bearerAuth(token))

	var resp railwayResponse
	if err := client.post(ctx, "/graphql/v2", map[string]string{
		"query": railwayProjectsQuery,
	}, &resp); err != nil {
		return nil, fmt.Errorf("railway: query projects: %w", err)
	}

	var assets []model.Asset
	now := time.Now().UTC()

	for _, edge := range resp.Data.Me.Projects.Edges {
		proj := edge.Node

		for _, svcEdge := range proj.Services.Edges {
			svc := svcEdge.Node
			assets = append(assets, railwayToAsset(proj, svc, now))
		}

		// If a project has no services, track the project itself.
		if len(proj.Services.Edges) == 0 {
			assets = append(assets, railwayProjectToAsset(proj, now))
		}
	}

	slog.Info("railway: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Railway GraphQL response types ---

type railwayResponse struct {
	Data struct {
		Me struct {
			Projects struct {
				Edges []struct {
					Node railwayProject `json:"node"`
				} `json:"edges"`
			} `json:"projects"`
		} `json:"me"`
	} `json:"data"`
}

type railwayProject struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Services     railwayEdges[railwayService]     `json:"services"`
	Environments railwayEdges[railwayEnvironment] `json:"environments"`
}

type railwayEdges[T any] struct {
	Edges []struct {
		Node T `json:"node"`
	} `json:"edges"`
}

type railwayService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

type railwayEnvironment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- Asset mapping ---

func railwayToAsset(proj railwayProject, svc railwayService, now time.Time) model.Asset {
	envNames := make([]string, 0, len(proj.Environments.Edges))
	for _, e := range proj.Environments.Edges {
		envNames = append(envNames, e.Node.Name)
	}

	tags := map[string]any{
		"platform":    "railway",
		"provider_id": svc.ID,
		"project":     proj.Name,
		"project_id":  proj.ID,
	}
	if svc.Icon != "" {
		tags["icon"] = svc.Icon
	}
	if len(envNames) > 0 {
		tags["environments"] = envNames
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        svc.Name,
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "railway",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}

func railwayProjectToAsset(proj railwayProject, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "railway",
		"provider_id": proj.ID,
		"warning":     "project has no services",
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        proj.Name,
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "railway",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
