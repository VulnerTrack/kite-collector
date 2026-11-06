package engine

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Keep each inventory record bounded. Every chunk carries the host identity,
// so a receiver can ingest it independently, including on unchanged rescans.
const inventorySoftwarePageSize = 200

func inventoryEvents(machine model.Machine, event model.MachineEvent, software []model.InstalledSoftware) ([]model.MachineEvent, error) {
	var base map[string]any
	_ = json.Unmarshal([]byte(event.Details), &base)
	if base == nil {
		base = make(map[string]any)
	}
	base["interfaces"] = machine.Interfaces
	// Preserve the complete discovered machine metadata separately from the
	// typed projections. Children are sent in their own fields/chunks.
	machine.Software = nil
	machine.Interfaces = nil
	base["inventory"] = machine
	pages := max(1, (len(software)+inventorySoftwarePageSize-1)/inventorySoftwarePageSize)
	out := make([]model.MachineEvent, 0, pages)
	for page := range pages {
		start := page * inventorySoftwarePageSize
		end := min(start+inventorySoftwarePageSize, len(software))
		base["software"] = software[start:end]
		base["inventory_chunk"] = page
		base["inventory_chunks"] = pages
		chunk := event
		if page > 0 {
			chunk.ID = uuid.Must(uuid.NewV7())
			// Inventory continuation is an observation, not another lifecycle
			// transition (or another unauthorized-machine alert).
			chunk.EventType = model.EventMachineAnalyzed
			chunk.Severity = model.SeverityLow
			base["event_type"] = string(chunk.EventType)
			base["event_name"] = chunk.EventType.Name()
		}
		// The payload contains only JSON-compatible model fields.
		encoded, err := json.Marshal(base)
		if err != nil {
			return nil, err
		}
		chunk.Details = string(encoded)
		out = append(out, chunk)
	}
	return out, nil
}
