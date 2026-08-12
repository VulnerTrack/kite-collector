package osquery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	// callTimeout bounds a single RPC round-trip. osquery answers table scans
	// in milliseconds; anything near this limit means a wedged daemon, and the
	// edge battery pinned that a dead socket must fail fast, not hang.
	callTimeout = 30 * time.Second
)

// Client speaks the ExtensionManager protocol to a running osqueryd over its
// extensions socket (Thrift UDS on unix, named pipe on Windows). Each call
// dials a fresh connection: the socket accepts concurrent short-lived clients
// (verified by the sim's edge battery) and per-call dialing means no shared
// state to poison when a call is cut short by a context.
type Client struct {
	socket  string
	timeout time.Duration
	seq     atomic.Int32
}

// NewClient returns a client for the given extensions socket path.
func NewClient(socket string) *Client {
	return &Client{socket: socket, timeout: callTimeout}
}

// queryError is a query the daemon parsed and REJECTED (status.code != 0):
// bad SQL, unknown table, constraint-required table without a WHERE. Distinct
// from transport errors so callers can tell "osquery said no" from "osquery
// unreachable" — the circuit-breaker cares about the latter.
type queryError struct {
	code    int32
	message string
}

func (e *queryError) Error() string {
	return fmt.Sprintf("osquery rejected query (code %d): %s", e.code, e.message)
}

// IsQueryError reports whether err is a daemon-side query rejection rather
// than a transport failure.
func IsQueryError(err error) bool {
	var qe *queryError
	return errors.As(err, &qe)
}

// Query runs sql against the daemon and returns its rows. A nil error with
// zero rows is a REAL result state, not a degenerate one: per the sim's edge
// battery, a missing YARA sigfile, an uncompilable sigfile, or a missing scan
// target all return rc=0 with an empty set. Callers must never read "no rows"
// as proof a scan ran.
func (c *Client) Query(ctx context.Context, sql string) ([]map[string]string, error) {
	rows, _, err := c.call(ctx, "query", sql)
	return rows, err
}

// Ping checks daemon liveness over the socket.
func (c *Client) Ping(ctx context.Context) error {
	_, _, err := c.call(ctx, "ping", "")
	return err
}

// call performs one Thrift RPC. For "query" the sql is sent as field 1; for
// "ping" the args struct is empty.
func (c *Client) call(ctx context.Context, method, sql string) ([]map[string]string, extensionStatus, error) {
	var status extensionStatus

	conn, err := dialSocket(ctx, c.socket, c.timeout)
	if err != nil {
		return nil, status, fmt.Errorf("osquery: dial %s: %w", c.socket, err)
	}
	defer func() { _ = conn.Close() }()

	// Honor both the client timeout and the caller's context deadline.
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Cancel a blocked read/write when the context fires mid-call.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	seq := c.seq.Add(1)

	w := newThriftWriter(conn)
	w.writeMessageBegin(method, mCALL, seq)
	if method == "query" {
		w.writeFieldBegin(tSTRING, 1)
		w.writeString(sql)
	}
	w.writeFieldStop()
	if ferr := w.flush(); ferr != nil {
		return nil, status, fmt.Errorf("osquery: send %s: %w", method, ferr)
	}

	r := newThriftReader(conn)
	mtype, _, err := r.readMessageBegin()
	if err != nil {
		return nil, status, fmt.Errorf("osquery: read %s reply: %w", method, err)
	}
	if mtype == mEXCEPTION {
		return nil, status, fmt.Errorf("osquery: %s: %w", method, r.readApplicationException())
	}
	if mtype != mREPLY {
		return nil, status, fmt.Errorf("osquery: unexpected message type %d", mtype)
	}

	// The reply is a result struct whose field 0 is the return value.
	var rows []map[string]string
	for {
		ftype, id, err := r.readFieldBegin()
		if err != nil {
			return nil, status, fmt.Errorf("osquery: decode %s result: %w", method, err)
		}
		if ftype == tSTOP {
			break
		}
		if id != 0 || ftype != tSTRUCT {
			if serr := r.skip(ftype, 0); serr != nil {
				return nil, status, fmt.Errorf("osquery: skip result field: %w", serr)
			}
			continue
		}
		switch method {
		case "ping":
			// ping returns ExtensionStatus directly.
			status, err = r.readExtensionStatus()
		default:
			// query returns ExtensionResponse{1: status, 2: rows}.
			rows, status, err = readExtensionResponse(r)
		}
		if err != nil {
			return nil, status, fmt.Errorf("osquery: decode %s payload: %w", method, err)
		}
	}

	if status.Code != 0 {
		return nil, status, &queryError{code: status.Code, message: status.Message}
	}
	return rows, status, nil
}

// readExtensionResponse decodes ExtensionResponse{1: ExtensionStatus, 2: rows}.
func readExtensionResponse(r *thriftReader) ([]map[string]string, extensionStatus, error) {
	var (
		status extensionStatus
		rows   []map[string]string
	)
	for {
		ftype, id, err := r.readFieldBegin()
		if err != nil {
			return nil, status, err
		}
		if ftype == tSTOP {
			return rows, status, nil
		}
		switch {
		case id == 1 && ftype == tSTRUCT:
			status, err = r.readExtensionStatus()
		case id == 2 && ftype == tLIST:
			rows, err = r.readRows()
		default:
			err = r.skip(ftype, 0)
		}
		if err != nil {
			return nil, status, err
		}
	}
}

// QueryOne runs sql and returns the first row, or nil when the result set is
// empty. Sugar for the single-row identity tables (osquery_info, system_info,
// os_version).
func (c *Client) QueryOne(ctx context.Context, sql string) (map[string]string, error) {
	rows, err := c.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// atoi converts osquery's stringly-typed numerics, tolerating empty values.
func atoi(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// dialSocket connects to an extensions socket path. Unix domain socket on
// every platform except when the path names a Windows pipe (\\.\pipe\...),
// which socket_windows.go handles; on non-Windows platforms a pipe path is
// rejected up front so the error names the real problem.
func dialSocket(ctx context.Context, path string, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return platformDial(dctx, path)
}
