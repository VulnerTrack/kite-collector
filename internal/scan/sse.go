package scan

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteSSEEvent writes one Server-Sent Events frame to w in the format
// required by the HTML5 spec: `event: <name>\n` + one or more `data: <line>\n`
// lines + a terminating blank line. The data payload is JSON-encoded; a
// marshal failure is surfaced as the returned error and nothing is written.
// Callers are responsible for invoking flusher.Flush() after a successful
// call when they need the frame delivered immediately.
func WriteSSEEvent(w io.Writer, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sse marshal %q: %w", event, err)
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return fmt.Errorf("sse write %q: %w", event, err)
	}
	return nil
}

// SSEEventName maps a coordinator EventType onto the SSE event name used on
// the wire. Unknown types fall through to "message" — the default per the
// SSE spec — so subscribers always receive a named frame even if the
// coordinator introduces a new type in a future phase.
func SSEEventName(t EventType) string {
	switch t {
	case EventStatus:
		return "status"
	case EventProgress:
		return "progress"
	case EventDone:
		return "done"
	default:
		return "message"
	}
}
