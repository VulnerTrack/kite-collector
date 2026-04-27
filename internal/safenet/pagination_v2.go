package safenet

import "fmt"

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
	Iterations int
	BytesTotal int64
	Message    string
}

func (e *PaginationGuardError) Error() string { return e.Message }

// PaginationGuardV2 extends PaginationGuard with byte caps. All caps default
// to safe values when the corresponding field is zero, so a zero-value
// PaginationGuardV2{} is usable directly.
type PaginationGuardV2 struct {
	MaxIterations   int
	MaxBytesPerPage int64
	MaxBytesTotal   int64

	iterations int
	bytesTotal int64
}

// NewPaginationGuardV2 returns a guard with production defaults: 10K
// iterations, 10 MiB per page, 100 MiB total. Operators can read overrides
// from env vars via PaginationCapsFromEnv.
func NewPaginationGuardV2() *PaginationGuardV2 {
	maxPage, maxTotal := PaginationCapsFromEnv()
	return &PaginationGuardV2{
		MaxIterations:   MaxPaginationIterations,
		MaxBytesPerPage: maxPage,
		MaxBytesTotal:   maxTotal,
	}
}

// NextPage records that one more page was fetched and contributed pageBytes
// to the cumulative total. It returns an error if any cap is exceeded.
//
// pageBytes may be 0 when the connector has not yet wired byte counting; in
// that case only the iteration cap is enforced (matching legacy
// PaginationGuard semantics).
func (g *PaginationGuardV2) NextPage(pageBytes int64) error {
	g.fillDefaults()

	g.iterations++
	if g.iterations > g.MaxIterations {
		return &PaginationGuardError{
			Reason:     PaginationCapIterations,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal,
			Message: fmt.Sprintf(
				"pagination exceeded %d iterations — possible infinite loop or "+
					"API reporting incorrect totals", g.MaxIterations),
		}
	}

	if pageBytes < 0 {
		return fmt.Errorf("pagination guard: negative pageBytes %d", pageBytes)
	}

	if pageBytes > g.MaxBytesPerPage {
		return &PaginationGuardError{
			Reason:     PaginationCapPageBytes,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal + pageBytes,
			Message: fmt.Sprintf(
				"pagination page size %d bytes exceeds per-page cap %d "+
					"(KITE_PAGINATION_MAX_BYTES_PER_PAGE)",
				pageBytes, g.MaxBytesPerPage),
		}
	}

	g.bytesTotal += pageBytes
	if g.bytesTotal > g.MaxBytesTotal {
		return &PaginationGuardError{
			Reason:     PaginationCapTotalBytes,
			Iterations: g.iterations,
			BytesTotal: g.bytesTotal,
			Message: fmt.Sprintf(
				"pagination cumulative %d bytes exceeds total cap %d "+
					"(KITE_PAGINATION_MAX_BYTES_TOTAL)",
				g.bytesTotal, g.MaxBytesTotal),
		}
	}

	return nil
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
