package osquery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOsqueryd is an in-process ExtensionManager: it accepts connections on a
// real unix socket and answers each call through respond. It exercises the
// client over the exact transport a live osqueryd uses.
type fakeOsqueryd struct {
	t       *testing.T
	ln      net.Listener
	socket  string
	respond func(method, sql string, seq int32) []byte
	wg      sync.WaitGroup
}

// newFakeOsqueryd starts the fake on a short-path socket (sun_path caps at
// ~104 bytes; t.TempDir can exceed it).
func newFakeOsqueryd(t *testing.T, respond func(method, sql string, seq int32) []byte) *fakeOsqueryd {
	t.Helper()
	dir, err := os.MkdirTemp("", "osq")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "em.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	require.NoError(t, err)

	f := &fakeOsqueryd{t: t, ln: ln, socket: socket, respond: respond}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *fakeOsqueryd) close() {
	_ = f.ln.Close()
	f.wg.Wait()
}

func (f *fakeOsqueryd) serve() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer func() { _ = conn.Close() }()
			f.handle(conn)
		}()
	}
}

// handle parses one call and writes whatever respond returns (nil = hang
// until the client gives up).
func (f *fakeOsqueryd) handle(conn net.Conn) {
	r := newThriftReader(conn)
	head, err := r.readI32()
	if err != nil || uint32(head)&0xffff0000 != thriftVersion1 { //#nosec G115 -- header word reinterpretation is the protocol
		return
	}
	method, err := r.readString()
	if err != nil {
		return
	}
	seq, err := r.readI32()
	if err != nil {
		return
	}
	var sql string
	for { // args struct
		ftype, id, err := r.readFieldBegin()
		if err != nil {
			return
		}
		if ftype == tSTOP {
			break
		}
		if id == 1 && ftype == tSTRING {
			if sql, err = r.readString(); err != nil {
				return
			}
			continue
		}
		if err := r.skip(ftype, 0); err != nil {
			return
		}
	}
	var reply []byte
	if f.respond != nil {
		reply = f.respond(method, sql, seq)
	}
	if reply != nil {
		_, _ = conn.Write(reply)
	} else {
		// Hang: hold the conn open until the client's deadline closes it.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}
}

// --- reply builders --------------------------------------------------------

func replyHeader(e *enc, method string, seq int32) *enc {
	return e.i32(msgHead(mREPLY)).str(method).i32(seq)
}

// queryReply builds a full ExtensionResponse reply.
func queryReply(seq int32, code int32, msg string, rows []map[string]string, order [][]string) []byte {
	e := replyHeader(&enc{}, "query", seq)
	e.byte1(tSTRUCT).i16(0)       // result field 0
	e.byte1(tSTRUCT).i16(1)       // ExtensionResponse.status
	encodeStatus(e, code, msg, 1) // (writes its own STOP)
	e.byte1(tLIST).i16(2)         // ExtensionResponse.response
	encodeRows(e, rows, order)    //
	e.byte1(tSTOP)                // end ExtensionResponse
	e.byte1(tSTOP)                // end result struct
	return e.bytes()
}

func pingReply(seq, code int32, msg string) []byte {
	e := replyHeader(&enc{}, "ping", seq)
	e.byte1(tSTRUCT).i16(0)
	encodeStatus(e, code, msg, 1)
	e.byte1(tSTOP)
	return e.bytes()
}

func exceptionReply(seq int32, msg string, typ int32) []byte {
	e := (&enc{}).i32(msgHead(mEXCEPTION)).str("query").i32(seq)
	e.byte1(tSTRING).i16(1).str(msg)
	e.byte1(tI32).i16(2).i32(typ)
	e.byte1(tSTOP)
	return e.bytes()
}

func okRows(rows []map[string]string, order [][]string) func(string, string, int32) []byte {
	return func(method, _ string, seq int32) []byte {
		if method == "ping" {
			return pingReply(seq, 0, "")
		}
		return queryReply(seq, 0, "OK", rows, order)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

func TestClient_Query_SingleRow(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(
		[]map[string]string{{"version": "5.15.0", "pid": "1"}},
		[][]string{{"version", "pid"}}))
	rows, err := NewClient(f.socket).Query(context.Background(), "SELECT version, pid FROM osquery_info;")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "5.15.0", rows[0]["version"])
}

func TestClient_Query_ManyRows(t *testing.T) {
	var rows []map[string]string
	var order [][]string
	for i := 0; i < 500; i++ {
		rows = append(rows, map[string]string{"n": fmt.Sprintf("%d", i)})
		order = append(order, []string{"n"})
	}
	f := newFakeOsqueryd(t, okRows(rows, order))
	got, err := NewClient(f.socket).Query(context.Background(), "SELECT n FROM seq;")
	require.NoError(t, err)
	require.Len(t, got, 500)
	assert.Equal(t, "499", got[499]["n"])
}

func TestClient_Query_UnicodeValues(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(
		[]map[string]string{{"path": "/var/kite/päth with späces ✓.txt"}},
		[][]string{{"path"}}))
	rows, err := NewClient(f.socket).Query(context.Background(), "SELECT path FROM file_events;")
	require.NoError(t, err)
	assert.Equal(t, "/var/kite/päth with späces ✓.txt", rows[0]["path"])
}

func TestClient_Query_SQLReachesServerVerbatim(t *testing.T) {
	var gotSQL string
	f := newFakeOsqueryd(t, func(method, sql string, seq int32) []byte {
		gotSQL = sql
		return queryReply(seq, 0, "OK", nil, nil)
	})
	const q = "SELECT * FROM yara WHERE path = 'a''b';"
	_, err := NewClient(f.socket).Query(context.Background(), q)
	require.NoError(t, err)
	assert.Equal(t, q, gotSQL)
}

func TestClient_Ping_Healthy(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(nil, nil))
	assert.NoError(t, NewClient(f.socket).Ping(context.Background()))
}

func TestClient_QueryOne_FirstRow(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(
		[]map[string]string{{"a": "1"}, {"a": "2"}},
		[][]string{{"a"}, {"a"}}))
	row, err := NewClient(f.socket).QueryOne(context.Background(), "SELECT a FROM t;")
	require.NoError(t, err)
	assert.Equal(t, "1", row["a"])
}

// ---------------------------------------------------------------------------
// Empty state — the silent-zero contract
// ---------------------------------------------------------------------------

func TestClient_Query_EmptyResultIsNotAnError(t *testing.T) {
	// Pinned by the sim's edge battery: a missing sigfile / missing target is
	// rc=0 with zero rows. The client must surface exactly that — no error,
	// no rows — and never invent a distinction the wire doesn't carry.
	f := newFakeOsqueryd(t, okRows(nil, nil))
	rows, err := NewClient(f.socket).Query(context.Background(), "SELECT count FROM yara WHERE path='/x' AND sigfile='/missing.yar';")
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestClient_QueryOne_EmptyGivesNilRowNilError(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(nil, nil))
	row, err := NewClient(f.socket).QueryOne(context.Background(), "SELECT 1 WHERE 0;")
	require.NoError(t, err)
	assert.Nil(t, row)
}

// ---------------------------------------------------------------------------
// Error states
// ---------------------------------------------------------------------------

func TestClient_Query_DaemonRejection_IsQueryError(t *testing.T) {
	f := newFakeOsqueryd(t, func(method, sql string, seq int32) []byte {
		return queryReply(seq, 1, "no such table: kite_no_such_table", nil, nil)
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT * FROM kite_no_such_table;")
	require.Error(t, err)
	assert.True(t, IsQueryError(err), "daemon rejection must be a queryError")
	assert.Contains(t, err.Error(), "no such table")
	assert.Contains(t, err.Error(), "code 1")
}

func TestClient_Query_ConstraintRejectionMessageSurvives(t *testing.T) {
	f := newFakeOsqueryd(t, func(method, sql string, seq int32) []byte {
		return queryReply(seq, 1, "Table hash was queried without a required column in the WHERE clause", nil, nil)
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT * FROM hash;")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required column")
}

func TestClient_DeadSocket_FailsFast(t *testing.T) {
	start := time.Now()
	_, err := NewClient("/tmp/kite-osq-definitely-absent.sock").Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.False(t, IsQueryError(err), "transport failure must NOT read as a query error")
	assert.Less(t, time.Since(start), 5*time.Second, "dead socket must fail fast")
	assert.Contains(t, err.Error(), "dial")
}

func TestClient_ServerClosesEarly_TransportError(t *testing.T) {
	// A server that slams the door on accept: EOF mid-reply is a transport
	// error, never a query error.
	dir, err := os.MkdirTemp("", "osq")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "em.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, err = NewClient(socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.False(t, IsQueryError(err))
}

func TestClient_GarbageReply_BadVersion(t *testing.T) {
	f := newFakeOsqueryd(t, func(_, _ string, _ int32) []byte {
		return bytes.Repeat([]byte{0x42}, 32)
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad protocol version")
}

func TestClient_ExceptionReply_SurfacesMessage(t *testing.T) {
	f := newFakeOsqueryd(t, func(_, _ string, seq int32) []byte {
		return exceptionReply(seq, "unknown method 'query'", 1)
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "application exception")
	assert.Contains(t, err.Error(), "unknown method")
}

func TestClient_TruncatedReply_Errors(t *testing.T) {
	f := newFakeOsqueryd(t, func(_, _ string, seq int32) []byte {
		full := queryReply(seq, 0, "OK", []map[string]string{{"a": "1"}}, [][]string{{"a"}})
		return full[:len(full)-3]
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
}

func TestClient_Ping_UnhealthyCode(t *testing.T) {
	f := newFakeOsqueryd(t, func(method, _ string, seq int32) []byte {
		return pingReply(seq, 2, "shutting down")
	})
	err := NewClient(f.socket).Ping(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutting down")
}

// ---------------------------------------------------------------------------
// Pending / async states
// ---------------------------------------------------------------------------

func TestClient_PendingReply_ContextTimeoutCutsItOff(t *testing.T) {
	f := newFakeOsqueryd(t, nil) // nil respond = server never answers
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewClient(f.socket).Query(ctx, "SELECT 1;")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second,
		"a hung daemon must not stall the scan beyond the context deadline")
}

func TestClient_PendingReply_SlowButWithinDeadlineSucceeds(t *testing.T) {
	f := newFakeOsqueryd(t, func(method, _ string, seq int32) []byte {
		time.Sleep(150 * time.Millisecond) // pending...
		return queryReply(seq, 0, "OK", []map[string]string{{"late": "yes"}}, [][]string{{"late"}})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := NewClient(f.socket).Query(ctx, "SELECT 1;")
	require.NoError(t, err)
	assert.Equal(t, "yes", rows[0]["late"])
}

func TestClient_ContextCancelledMidCall(t *testing.T) {
	f := newFakeOsqueryd(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := NewClient(f.socket).Query(ctx, "SELECT 1;")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestClient_ConcurrentQueries_AllAnswer(t *testing.T) {
	f := newFakeOsqueryd(t, okRows(
		[]map[string]string{{"ok": "1"}}, [][]string{{"ok"}}))
	client := NewClient(f.socket)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, errs[n] = client.Query(context.Background(), "SELECT 1;")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "concurrent call %d", i)
	}
}

func TestClient_SequentialCallsReuseNothing(t *testing.T) {
	// Two calls, two fresh connections — the second must succeed even after
	// the first conn is gone.
	f := newFakeOsqueryd(t, okRows(nil, nil))
	c := NewClient(f.socket)
	for i := 0; i < 3; i++ {
		_, err := c.Query(context.Background(), "SELECT 1;")
		require.NoError(t, err, "call %d", i)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func TestIsQueryError_PlainErrorIsFalse(t *testing.T) {
	assert.False(t, IsQueryError(errors.New("dial: no such file")))
	assert.False(t, IsQueryError(nil))
}

func TestIsQueryError_WrappedQueryErrorIsTrue(t *testing.T) {
	err := fmt.Errorf("outer: %w", &queryError{code: 1, message: "x"})
	assert.True(t, IsQueryError(err))
}

func TestAtoi_Tolerant(t *testing.T) {
	cases := map[string]int64{
		"": 0, "0": 0, "42": 42, "-7": -7, "garbage": 0, "9223372036854775807": 9223372036854775807,
	}
	for in, want := range cases {
		assert.Equal(t, want, atoi(in), "atoi(%q)", in)
	}
}

// ---------------------------------------------------------------------------
// Error-state audit additions: protocol desync + method-honest rejections
// ---------------------------------------------------------------------------

func TestClient_MismatchedSequenceID_IsProtocolDesync(t *testing.T) {
	// A reply carrying a different sequence id than the call must be
	// rejected: decoding it as this call's answer would silently attribute
	// another call's rows or errors to this query.
	f := newFakeOsqueryd(t, func(method, _ string, seq int32) []byte {
		return queryReply(seq+1, 0, "OK", []map[string]string{{"a": "1"}}, [][]string{{"a"}})
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sequence id")
	assert.False(t, IsQueryError(err), "desync is a protocol failure, not a daemon rejection")
}

func TestClient_PingRejection_MessageNamesPing(t *testing.T) {
	// A failed ping is a daemon-health signal; its error must not read
	// "rejected query".
	f := newFakeOsqueryd(t, func(method, _ string, seq int32) []byte {
		return pingReply(seq, 2, "shutting down")
	})
	err := NewClient(f.socket).Ping(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected ping")
	assert.NotContains(t, err.Error(), "rejected query")
}

func TestClient_QueryRejection_MessageNamesQuery(t *testing.T) {
	f := newFakeOsqueryd(t, func(method, _ string, seq int32) []byte {
		return queryReply(seq, 1, "no such table", nil, nil)
	})
	_, err := NewClient(f.socket).Query(context.Background(), "SELECT 1;")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected query")
}
