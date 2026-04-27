package emitter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// FuzzBuildPayload_DoesNotPanic exercises buildPayload + json.Marshal with
// fuzz-driven AssetEvent inputs. Goal: prove the OTLP wire encoder never
// panics on hostile strings (null bytes, lone surrogates, JSON metachars,
// pathological lengths) and that the produced payload is always valid JSON
// that re-parses to the same shape.
//
// The seed corpus pins the obvious edge cases so they run as deterministic
// asserts during every `go test ./...` (Go's built-in fuzz harness replays
// seeds as unit tests). `make fuzz-quick` then explores random mutations.
func FuzzBuildPayload_DoesNotPanic(f *testing.F) {
	// Well-formed baseline.
	f.Add(
		"AssetDiscovered", "high", "host-01", "server",
		`{"event_type":"AssetDiscovered"}`,
	)
	// Empty everywhere.
	f.Add("", "", "", "", "")
	// JSON metacharacters that must be escaped in the body.
	f.Add(
		"AssetUpdated", "low", `host"with\quote`, "container",
		`{"k":"v\nwith\u0000null"}`,
	)
	// Control characters 0x00-0x1f in every string slot.
	f.Add(
		"AssetRemoved", "critical", "\x00\x01\x02host", "server",
		"\x00\x1f\x7f",
	)
	// Invalid UTF-8 (lone continuation + surrogate halves).
	f.Add(
		string([]byte{0xff, 0xfe, 0xfd}), "medium",
		string([]byte{0xed, 0xa0, 0x80}), // U+D800 lone high surrogate
		"workstation",
		string([]byte{0xc0, 0xc1}), // overlong / invalid
	)
	// Pathologically long strings (1 KiB each — kept small so seed pass is fast).
	long := make([]byte, 1024)
	for i := range long {
		long[i] = 'A' + byte(i%26)
	}
	f.Add("UnauthorizedAssetDetected", "high", string(long), string(long), string(long))

	o := &OTLPEmitter{
		serviceName:    "kite-collector",
		serviceVersion: "fuzz",
	}

	f.Fuzz(func(t *testing.T, eventType, severity, hostname, assetType, details string) {
		evt := model.AssetEvent{
			Timestamp: time.Unix(0, 0),
			EventType: model.EventType(eventType),
			Severity:  model.Severity(severity),
			Hostname:  hostname,
			AssetType: model.AssetType(assetType),
			Details:   details,
			ID:        uuid.Must(uuid.NewV7()),
			AssetID:   uuid.Must(uuid.NewV7()),
			ScanRunID: uuid.Must(uuid.NewV7()),
		}

		payload := o.buildPayload([]model.AssetEvent{evt})

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal must not fail on any input: %v", err)
		}

		var roundTrip otlpLogsPayload
		if err := json.Unmarshal(body, &roundTrip); err != nil {
			t.Fatalf("round-trip unmarshal failed: %v\nbody=%s", err, body)
		}
		if got, want := len(roundTrip.ResourceLogs), 1; got != want {
			t.Fatalf("resourceLogs length: got %d want %d", got, want)
		}
		if got, want := len(roundTrip.ResourceLogs[0].ScopeLogs), 1; got != want {
			t.Fatalf("scopeLogs length: got %d want %d", got, want)
		}
		if got, want := len(roundTrip.ResourceLogs[0].ScopeLogs[0].LogRecords), 1; got != want {
			t.Fatalf("logRecords length: got %d want %d", got, want)
		}
	})
}
