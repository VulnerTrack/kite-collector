package safenet

import (
	"fmt"
)

const (
	// DefaultMaxBytesPerPage is the per-response-body cap (10 MiB).
	DefaultMaxBytesPerPage int64 = 10 * 1024 * 1024

	// DefaultMaxBytesTotal is the cumulative cross-page cap (100 MiB).
	DefaultMaxBytesTotal int64 = 100 * 1024 * 1024
)

// PaginationCapReason names the specific guard that fired and is suitable
// for use as a SafetyGuardEvent.guard_type value.
type PaginationCapReason string

const (
	PaginationCapIterations  PaginationCapReason = "pagination_iteration_cap"
	PaginationCapPageBytes   PaginationCapReason = "pagination_byte_cap"
	PaginationCapTotalBytes  PaginationCapReason = "pagination_byte_cap"
	PaginationCapNotExceeded PaginationCapReason = ""
)

// PaginationGuardError is returned by PaginationGuardV2 when a cap is hit.
// Callers can extract Reason for logging and for SafetyGuardEvent rows.
type PaginationGuardError struct {
	Reason     PaginationCapReason
	Message    string
	Iterations int
	BytesTotal int64
}

func (e *PaginationGuardError) Error() string { return e.Message }

// PaginationGuardV2 extends PaginationGuard with byte caps. All caps default
// to safe values when the corresponding field is zero, so a zero-value
// PaginationGuardV2{} is usable directly.
//
// Source identifies the connector for telemetry (e.g. "heroku", "wazuh",
// "linode"). It feeds GuardEvent.SourceComponent and the
// kite_pagination_truncated_total{connector=...} counter. Empty Source is
// allowed but produces unattributed events, so connectors should always
// pass a stable name via NewPaginationGuardV2WithSource.
type PaginationGuardV2 struct {
	Source          string
	MaxIterations   int
	MaxBytesPerPage int64
	MaxBytesTotal   int64

	iterations int
	bytesTotal int64
}

// NewPaginationGuardV2 returns a guard with production defaults: 10K
// iterations, 10 MiB per page, 100 MiB total. Operators can read overrides
// from env vars via PaginationCapsFromEnv. Source is left empty; prefer
// NewPaginationGuardV2WithSource so guard events are attributed.
func NewPaginationGuardV2() *PaginationGuardV2 {
	return NewPaginationGuardV2WithSource("")
}

// NewPaginationGuardV2WithSource returns a guard tagged with the provided
// connector name. Use this in HTTP discovery connectors so Prometheus
// counters and SafetyGuardEvent rows can be attributed back to the
// upstream API.
func NewPaginationGuardV2WithSource(source string) *PaginationGuardV2 {
	maxPage, maxTotal := PaginationCapsFromEnv()
	return &PaginationGuardV2{
		MaxIterations:   MaxPaginationIterations,
		MaxBytesPerPage: maxPage,
		MaxBytesTotal:   maxTotal,
		Source:          source,
	}
}

// NextPage records that one more page was fetched and contributed pageBytes
// to the cumulative total. It returns an error if any cap is exceeded.
//
// pageBytes may be 0 when the connector has not yet wired byte counting; in
// that case only the iteration cap is enforced (matching legacy
// PaginationGuard semantics).
//
// Each cap-fire emits a GuardEvent via emitGuardEvent so observers (e.g.
// the metrics package) can increment counters without coupling safenet to
// any specific telemetry stack.
func (g *PaginationGuardV2) NextPage(pageBytes int64) error {
	g.fillDefaults()

	g.iterations++
	if g.iterations > g.MaxIterations {
		err := &PaginationGuardError{
			Reason:     PaginationCapIterations,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal,
			Message: fmt.Sprintf(
				"pagination exceeded %d iterations — possible infinite loop or "+
					"API reporting incorrect totals", g.MaxIterations,
			),
		}
		g.emitCap(err)
		return err
	}

	if pageBytes < 0 {
		return fmt.Errorf("pagination guard: negative pageBytes %d", pageBytes)
	}

	if pageBytes > g.MaxBytesPerPage {
		err := &PaginationGuardError{
			Reason:     PaginationCapPageBytes,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal + pageBytes,
			Message: fmt.Sprintf(
				"pagination page size %d bytes exceeds per-page cap %d "+
					"(KITE_PAGINATION_MAX_BYTES_PER_PAGE)",
				pageBytes, g.MaxBytesPerPage,
			),
		}
		g.emitCap(err)
		return err
	}

	g.bytesTotal += pageBytes
	if g.bytesTotal > g.MaxBytesTotal {
		err := &PaginationGuardError{
			Reason:     PaginationCapTotalBytes,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal,
			Message: fmt.Sprintf(
				"pagination cumulative %d bytes exceeds total cap %d "+
					"(KITE_PAGINATION_MAX_BYTES_TOTAL)",
				g.bytesTotal, g.MaxBytesTotal,
			),
		}
		g.emitCap(err)
		return err
	}

	return nil
}

// emitCap publishes a GuardEvent describing the cap that fired. The
// SourceComponent field carries the connector name so Prometheus labels
// can attribute the truncation back to the upstream API.
func (g *PaginationGuardV2) emitCap(err *PaginationGuardError) {
	source := g.Source
	if source == "" {
		source = "pagination_guard"
	}
	details := fmt.Sprintf(
		`{"iterations":%d,"bytes_total":%d,"max_iterations":%d,`+
			`"max_bytes_per_page":%d,"max_bytes_total":%d}`,
		err.Iterations, err.BytesTotal, g.MaxIterations,
		g.MaxBytesPerPage, g.MaxBytesTotal,
	)
	emitGuardEvent(NewGuardEvent(
		GuardEventType(err.Reason),
		GuardActionCapped,
		source,
		err.Message,
		details,
	))
}

// Next is a backward-compatible shim equivalent to NextPage(0). It allows
// connectors to migrate to V2 in two steps: first swap PaginationGuard for
// PaginationGuardV2 (only iteration cap enforced), then add byte counts.
func (g *PaginationGuardV2) Next() error { return g.NextPage(0) }

// Iterations returns the number of NextPage calls observed so far.
func (g *PaginationGuardV2) Iterations() int { return g.iterations }

// BytesTotal returns the cumulative byte count observed so far.
func (g *PaginationGuardV2) BytesTotal() int64 { return g.bytesTotal }

func (g *PaginationGuardV2) fillDefaults() {
	if g.MaxIterations <= 0 {
		g.MaxIterations = MaxPaginationIterations
	}
	if g.MaxBytesPerPage <= 0 {
		g.MaxBytesPerPage = DefaultMaxBytesPerPage
	}
	if g.MaxBytesTotal <= 0 {
		g.MaxBytesTotal = DefaultMaxBytesTotal
	}
}

// PaginationCapsFromEnv returns the per-page and total byte caps configured
// via KITE_PAGINATION_MAX_BYTES_PER_PAGE and KITE_PAGINATION_MAX_BYTES_TOTAL,
// falling back to defaults on missing or invalid values.
func PaginationCapsFromEnv() (perPage, total int64) {
	perPage = int64(positiveIntEnv("KITE_PAGINATION_MAX_BYTES_PER_PAGE",
		int(DefaultMaxBytesPerPage)))
	total = int64(positiveIntEnv("KITE_PAGINATION_MAX_BYTES_TOTAL",
		int(DefaultMaxBytesTotal)))
	return perPage, total
}
