package dedup

// LogCode is the typed identifier attached to every structured log
// entry the dedup package emits. Convention: `dedup.<surface>.<event>`
// so downstream tooling can pivot on a stable identifier without
// parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// batch surface — per-batch deduplication telemetry
	LogCodeDedupSkipIntraBatch LogCode = "dedup.batch.skip_intra_batch"
	LogCodeDedupUpdated        LogCode = "dedup.batch.updated"
	LogCodeDedupNew            LogCode = "dedup.batch.new"
	LogCodeDedupCompleted      LogCode = "dedup.batch.completed"
)
