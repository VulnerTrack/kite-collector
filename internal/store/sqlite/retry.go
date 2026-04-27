package sqlite

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTransientStorageExhausted is the sentinel returned by
// withTransientRetry when every attempt to commit a transaction failed
// with a transient SQLite I/O error. Callers (e.g. the scan
// coordinator) detect this with errors.Is and surface a remediation
// hint pointing at sync/network/AV interference.
var ErrTransientStorageExhausted = errors.New("transient storage error retries exhausted")

// transientErrorNeedles are substrings produced by modernc.org/sqlite
// for errors that are almost always caused by external processes
// (cloud-sync agents, antivirus, backup tools) racing the DB ancillary
// files (WAL/SHM/journal). Matching the family rather than every
// individual extended code keeps the logic readable and forward-
// compatible with future SQLite extended codes.
var transientErrorNeedles = []string{
	"disk i/o error",           // SQLITE_IOERR (10) and any extended *_IOERR_*
	"database is locked",       // SQLITE_BUSY (5)
	"database table is locked", // SQLITE_LOCKED (6)
}

// isTransientSQLiteErr reports whether err matches one of the known
// transient SQLite error families.
func isTransientSQLiteErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, n := range transientErrorNeedles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

// withTransientRetry runs fn up to maxAttempts times, retrying on
// transient SQLite I/O errors. The transaction either committed or
// rolled back atomically before fn returned, so re-running the full
// operation from a fresh tx is safe.
//
// Backoff is 25 ms × attempt² (i.e. 25, 100, 225, 400 ms ...) to give
// any racing process enough time to release the ancillary file. The
// final error is wrapped with ErrTransientStorageExhausted so callers
// can detect retry exhaustion with errors.Is.
func withTransientRetry(maxAttempts int, fn func() error) error {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !isTransientSQLiteErr(err) {
			return err
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt*attempt) * 25 * time.Millisecond)
		}
	}
	return fmt.Errorf("%w after %d attempts: %v", ErrTransientStorageExhausted, maxAttempts, lastErr)
}
