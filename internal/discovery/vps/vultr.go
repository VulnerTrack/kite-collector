package vps

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Vultr implements discovery.Source for the Vultr API v2.
type Vultr struct {
	baseURL string
}

// NewVultr returns a new Vultr discovery source.
func NewVultr() *Vultr {
	return &Vultr{baseURL: "https://api.vultr.com/v2"}
}

// Name returns the stable identifier for this source.
func (v *Vultr) Name() string { return "vultr" }

// Discover lists all Vultr instances using cursor-based pagination.
// Credentials: KITE_VULTR_TOKEN environment variable.
func (v *Vultr) Discover(ctx context.Context, cfg map[string]any) ([]model.Machine, error) {
	token := os.Getenv("KITE_VULTR_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("vultr: KITE_VULTR_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("Vultr VPS discovery starting",
		"code", string(LogCodeVultrStarting))

	client := newClient("vultr", v.baseURL, bearerAuth(token))
	var machines []model.Machine
	cursor := ""
	guard := safenet.NewPaginationGuardV2WithSource("vultr")

	for {
		if ctx.Err() != nil {
			return machines, fmt.Errorf("vultr: context cancelled: %w", ctx.Err())
		}

		path := "/instances?per_page=100"
		if cursor != "" {
			path += "&cursor=" + cursor
		}

		var resp vultrInstancesResponse
		nBytes, err := client.getSized(ctx, path, &resp)
		if err != nil {
			return machines, fmt.Errorf("vultr: list instances: %w", err)
		}
		if err := guard.NextPage(nBytes); err != nil {
			return machines, fmt.Errorf("vultr: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Instances {
			machines = append(machines, vultrToMachine(resp.Instances[i], now))
		}

		raw := resp.Meta.Links.Next
		if raw == "" {
			break
		}
		clean, sanErr := safenet.SanitizeCursorWithSource("vultr", raw)
		if sanErr != nil {
			slog.Warn("Vultr pagination cursor rejected by safenet; stopping pagination",
				"code", string(LogCodeVultrPaginationRejected),
				"error", sanErr,
				"machines_so_far", len(machines))
			break
		}
		cursor = clean
	}

	slog.Info("Vultr VPS discovery complete",
		"code", string(LogCodeVultrComplete),
		"machines", len(machines))
	return machines, nil
}

// --- Vultr API response types ---

type vultrInstancesResponse struct {
	Meta      vultrMeta       `json:"meta"`
	Instances []vultrInstance `json:"instances"`
}

type vultrMeta struct {
	Links vultrLinks `json:"links"`
	Total int        `json:"total"`
}

type vultrLinks struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

type vultrInstance struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	OS          string   `json:"os"`
	Plan        string   `json:"plan"`
	Region      string   `json:"region"`
	Status      string   `json:"status"`
	MainIP      string   `json:"main_ip"`
	DateCreated string   `json:"date_created"`
	Tags        []string `json:"tags"`
}

// --- Machine mapping ---

func vultrToMachine(inst vultrInstance, now time.Time) model.Machine {
	tags := map[string]any{
		"provider_id": inst.ID,
		"ip":          inst.MainIP,
		"plan":        inst.Plan,
		"status":      inst.Status,
	}
	if len(inst.Tags) > 0 {
		tags["tags"] = inst.Tags
	}
	if inst.Status != "active" {
		tags["warning"] = "instance not active - not reachable by network scan"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, inst.DateCreated); err == nil {
		firstSeen = t
	}

	machine := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        inst.Label,
		MachineType:     model.MachineTypeCloudInstance,
		OSFamily:        inst.OS,
		Environment:     inst.Region,
		DiscoverySource: "vultr",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	machine.ComputeNaturalKey()
	return machine
}
