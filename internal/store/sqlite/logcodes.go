package sqlite

// LogCode is the typed identifier attached to every structured log
// entry the sqlite store package emits. Convention:
// `sqlitestore.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// The `sqlitestore` namespace deliberately differs from the bare
// package name `sqlite` because the bare word is ambiguous (the
// codebase imports both `database/sql` driver `sqlite` AND a separate
// vendor sqlite). `sqlitestore` makes it unambiguous in cross-tenant
// log indexes.
//
// Every Warn/Error site MUST include the code as a `"code"` structured
// attribute. Info sites should include one when they mark a notable
// state transition operators care about (migration apply, encrypted
// working copy events).
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// preflight surface — db_path sanity warnings before opening
	LogCodePreflightSyncVolume LogCode = "sqlitestore.preflight.db_path_sync_volume"
	LogCodePreflightUNCShare   LogCode = "sqlitestore.preflight.db_path_unc_share"
	LogCodePreflightNonLocalFS LogCode = "sqlitestore.preflight.db_path_non_local_fs"

	// encrypted surface — encrypted-at-rest working-copy lifecycle
	LogCodeEncryptedUsingRAMDir          LogCode = "sqlitestore.encrypted.using_ram_dir"
	LogCodeEncryptedNoRAMDir             LogCode = "sqlitestore.encrypted.no_ram_dir"
	LogCodeEncryptedNoTempDir            LogCode = "sqlitestore.encrypted.no_temp_dir"
	LogCodeEncryptedWeakKeyBackend       LogCode = "sqlitestore.encrypted.weak_key_backend"
	LogCodeEncryptedDecrypting           LogCode = "sqlitestore.encrypted.decrypting"
	LogCodeEncryptedMigratingUnencrypted LogCode = "sqlitestore.encrypted.migrating_unencrypted"
	LogCodeEncryptedEncryptingAtRest     LogCode = "sqlitestore.encrypted.encrypting_at_rest"
	LogCodeEncryptedRemoveWorkingFile    LogCode = "sqlitestore.encrypted.remove_working_file_failed"
	LogCodeEncryptedRemoveWorkdir        LogCode = "sqlitestore.encrypted.remove_workdir_failed"

	// migrate surface — schema migration apply / recovery
	LogCodeMigrateChecksumMismatch LogCode = "sqlitestore.migrate.checksum_mismatch"
	LogCodeMigrateApplying         LogCode = "sqlitestore.migrate.applying"
	LogCodeMigrateColumnExists     LogCode = "sqlitestore.migrate.column_exists_recovery"
	LogCodeMigrateApplied          LogCode = "sqlitestore.migrate.applied"
	LogCodeMigrateEntryRemoved     LogCode = "sqlitestore.migrate.entry_removed"
)
