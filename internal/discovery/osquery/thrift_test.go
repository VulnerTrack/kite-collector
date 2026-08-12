package osquery

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enc builds thrift-encoded bytes for tests. Each helper mirrors the wire
// format independently of thriftWriter so writer and reader are checked
// against the spec, not against each other.
type enc struct{ b bytes.Buffer }

func (e *enc) byte1(v byte) *enc     { e.b.WriteByte(v); return e }
func (e *enc) i16(v int16) *enc      { _ = binary.Write(&e.b, binary.BigEndian, v); return e }
func (e *enc) i32(v int32) *enc      { _ = binary.Write(&e.b, binary.BigEndian, v); return e }
func (e *enc) i64(v int64) *enc      { _ = binary.Write(&e.b, binary.BigEndian, v); return e }
func (e *enc) str(s string) *enc     { e.i32(int32(len(s))); e.b.WriteString(s); return e } //#nosec G115 -- test strings are tiny
func (e *enc) bytes() []byte         { return e.b.Bytes() }
func (e *enc) reader() *thriftReader { return newThriftReader(bytes.NewReader(e.b.Bytes())) }

// msgHead builds the strict-protocol message-header word without tripping
// Go's constant-overflow check (the OR sets the sign bit).
func msgHead(typ int32) int32 {
	return int32(uint32(thriftVersion1) | uint32(typ)) //#nosec G115 -- sign bit set by design
}

// ---------------------------------------------------------------------------
// Writer golden encodings
// ---------------------------------------------------------------------------

func TestThriftWriter_MessageBegin_GoldenBytes(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeMessageBegin("query", mCALL, 7)
	require.NoError(t, w.flush())

	want := (&enc{}).i32(msgHead(mCALL)).str("query").i32(7).bytes()
	assert.Equal(t, want, buf.Bytes())
}

func TestThriftWriter_FieldBegin_GoldenBytes(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeFieldBegin(tSTRING, 1)
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{tSTRING, 0x00, 0x01}, buf.Bytes())
}

func TestThriftWriter_FieldStop_IsZeroByte(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeFieldStop()
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{0x00}, buf.Bytes())
}

func TestThriftWriter_String_LengthPrefixed(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeString("ab")
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{0, 0, 0, 2, 'a', 'b'}, buf.Bytes())
}

func TestThriftWriter_EmptyString(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeString("")
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{0, 0, 0, 0}, buf.Bytes())
}

func TestThriftWriter_I16_BigEndian(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeI16(-2)
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{0xff, 0xfe}, buf.Bytes())
}

func TestThriftWriter_I32_BigEndian(t *testing.T) {
	var buf bytes.Buffer
	w := newThriftWriter(&buf)
	w.writeI32(0x01020304)
	require.NoError(t, w.flush())
	assert.Equal(t, []byte{1, 2, 3, 4}, buf.Bytes())
}

// ---------------------------------------------------------------------------
// Reader primitives — happy path
// ---------------------------------------------------------------------------

func TestThriftReader_ReadString_RoundTrip(t *testing.T) {
	r := (&enc{}).str("hello osquery").reader()
	got, err := r.readString()
	require.NoError(t, err)
	assert.Equal(t, "hello osquery", got)
}

func TestThriftReader_ReadString_Unicode(t *testing.T) {
	r := (&enc{}).str("päth wíth ünïcode — ✓").reader()
	got, err := r.readString()
	require.NoError(t, err)
	assert.Equal(t, "päth wíth ünïcode — ✓", got)
}

func TestThriftReader_ReadString_Empty(t *testing.T) {
	r := (&enc{}).str("").reader()
	got, err := r.readString()
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestThriftReader_ReadI64_RoundTrip(t *testing.T) {
	r := (&enc{}).i64(-9007199254740993).reader()
	got, err := r.readI64()
	require.NoError(t, err)
	assert.Equal(t, int64(-9007199254740993), got)
}

func TestThriftReader_MessageBegin_Reply(t *testing.T) {
	r := (&enc{}).i32(msgHead(mREPLY)).str("query").i32(42).reader()
	typ, seq, err := r.readMessageBegin()
	require.NoError(t, err)
	assert.Equal(t, int32(mREPLY), typ)
	assert.Equal(t, int32(42), seq)
}

func TestThriftReader_FieldBegin_StopNeedsNoID(t *testing.T) {
	r := (&enc{}).byte1(tSTOP).reader()
	ftype, id, err := r.readFieldBegin()
	require.NoError(t, err)
	assert.Equal(t, byte(tSTOP), ftype)
	assert.Equal(t, int16(0), id)
}

func TestThriftReader_FieldBegin_TypeAndID(t *testing.T) {
	r := (&enc{}).byte1(tSTRUCT).i16(2).reader()
	ftype, id, err := r.readFieldBegin()
	require.NoError(t, err)
	assert.Equal(t, byte(tSTRUCT), ftype)
	assert.Equal(t, int16(2), id)
}

// ---------------------------------------------------------------------------
// Reader — error and hostile-input states
// ---------------------------------------------------------------------------

func TestThriftReader_MessageBegin_BadVersion(t *testing.T) {
	r := (&enc{}).i32(0x00010002).str("x").i32(1).reader()
	_, _, err := r.readMessageBegin()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad protocol version")
}

func TestThriftReader_String_NegativeLengthRejected(t *testing.T) {
	r := (&enc{}).i32(-5).reader()
	_, err := r.readString()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestThriftReader_String_HugeLengthRejectedWithoutAllocating(t *testing.T) {
	// 2 GiB claimed length with 0 bytes behind it: must fail on the guard,
	// not attempt the allocation.
	r := (&enc{}).i32(2147483647).reader()
	_, err := r.readString()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestThriftReader_String_TruncatedBody(t *testing.T) {
	e := (&enc{}).i32(10)
	e.b.WriteString("short")
	_, err := e.reader().readString()
	require.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestThriftReader_EmptyInput_EOF(t *testing.T) {
	r := newThriftReader(strings.NewReader(""))
	_, err := r.readByte()
	require.Error(t, err)
	assert.ErrorIs(t, err, io.EOF)
}

func TestThriftReader_I16_Truncated(t *testing.T) {
	r := (&enc{}).byte1(0x01).reader()
	_, err := r.readI16()
	require.Error(t, err)
}

func TestThriftReader_I32_Truncated(t *testing.T) {
	r := (&enc{}).i16(1).reader()
	_, err := r.readI32()
	require.Error(t, err)
}

func TestThriftReader_I64_Truncated(t *testing.T) {
	r := (&enc{}).i32(1).reader()
	_, err := r.readI64()
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// skip — every type, plus recursion and container caps
// ---------------------------------------------------------------------------

func TestThriftSkip_Scalars(t *testing.T) {
	cases := []struct {
		name  string
		ftype byte
		build func(*enc)
	}{
		{"bool", tBOOL, func(e *enc) { e.byte1(1) }},
		{"byte", tBYTE, func(e *enc) { e.byte1(0xff) }},
		{"i16", tI16, func(e *enc) { e.i16(7) }},
		{"i32", tI32, func(e *enc) { e.i32(7) }},
		{"i64", tI64, func(e *enc) { e.i64(7) }},
		{"double", tDOUBLE, func(e *enc) { e.i64(4614256656552045848) }},
		{"string", tSTRING, func(e *enc) { e.str("skipped") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &enc{}
			tc.build(e)
			e.byte1(0xAA) // sentinel that must remain after the skip
			r := e.reader()
			require.NoError(t, r.skip(tc.ftype, 0))
			b, err := r.readByte()
			require.NoError(t, err)
			assert.Equal(t, byte(0xAA), b, "skip consumed too much or too little")
		})
	}
}

func TestThriftSkip_Struct(t *testing.T) {
	e := (&enc{}).byte1(tI32).i16(1).i32(99).byte1(tSTRING).i16(2).str("x").byte1(tSTOP)
	e.byte1(0xAA)
	r := e.reader()
	require.NoError(t, r.skip(tSTRUCT, 0))
	b, err := r.readByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0xAA), b)
}

func TestThriftSkip_NestedStruct(t *testing.T) {
	inner := (&enc{}).byte1(tI32).i16(1).i32(1).byte1(tSTOP)
	e := (&enc{}).byte1(tSTRUCT).i16(1)
	e.b.Write(inner.bytes())
	e.byte1(tSTOP).byte1(0xAA)
	r := e.reader()
	require.NoError(t, r.skip(tSTRUCT, 0))
	b, err := r.readByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0xAA), b)
}

func TestThriftSkip_Map(t *testing.T) {
	e := (&enc{}).byte1(tSTRING).byte1(tI32).i32(2).str("a").i32(1).str("b").i32(2)
	e.byte1(0xAA)
	r := e.reader()
	require.NoError(t, r.skip(tMAP, 0))
	b, err := r.readByte()
	require.NoError(t, err)
	assert.Equal(t, byte(0xAA), b)
}

func TestThriftSkip_ListAndSet(t *testing.T) {
	for _, typ := range []byte{tLIST, tSET} {
		e := (&enc{}).byte1(tSTRING).i32(2).str("one").str("two")
		e.byte1(0xAA)
		r := e.reader()
		require.NoError(t, r.skip(typ, 0))
		b, err := r.readByte()
		require.NoError(t, err)
		assert.Equal(t, byte(0xAA), b)
	}
}

func TestThriftSkip_UnknownTypeErrors(t *testing.T) {
	r := (&enc{}).byte1(0x00).reader()
	err := r.skip(99, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown type")
}

func TestThriftSkip_RecursionDepthCapped(t *testing.T) {
	// A chain of nested struct fields deeper than maxSkipDepth must error,
	// not blow the stack.
	e := &enc{}
	for i := 0; i < maxSkipDepth+2; i++ {
		e.byte1(tSTRUCT).i16(1)
	}
	err := e.reader().skip(tSTRUCT, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recursion")
}

func TestThriftSkip_MapSizeCapped(t *testing.T) {
	r := (&enc{}).byte1(tSTRING).byte1(tSTRING).i32(maxThriftContainer + 1).reader()
	err := r.skip(tMAP, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestThriftSkip_ListSizeCapped(t *testing.T) {
	r := (&enc{}).byte1(tSTRING).i32(-1).reader()
	err := r.skip(tLIST, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

// ---------------------------------------------------------------------------
// ExtensionStatus / rows / exception decoding
// ---------------------------------------------------------------------------

// encodeStatus writes an ExtensionStatus struct body.
func encodeStatus(e *enc, code int32, msg string, uuid int64) *enc {
	e.byte1(tI32).i16(1).i32(code)
	e.byte1(tSTRING).i16(2).str(msg)
	e.byte1(tI64).i16(3).i64(uuid)
	e.byte1(tSTOP)
	return e
}

func TestReadExtensionStatus_AllFields(t *testing.T) {
	r := encodeStatus(&enc{}, 1, "no such table: nope", 77).reader()
	st, err := r.readExtensionStatus()
	require.NoError(t, err)
	assert.Equal(t, int32(1), st.Code)
	assert.Equal(t, "no such table: nope", st.Message)
	assert.Equal(t, int64(77), st.UUID)
}

func TestReadExtensionStatus_EmptyStruct(t *testing.T) {
	r := (&enc{}).byte1(tSTOP).reader()
	st, err := r.readExtensionStatus()
	require.NoError(t, err)
	assert.Equal(t, int32(0), st.Code)
	assert.Equal(t, "", st.Message)
}

func TestReadExtensionStatus_UnknownFieldSkipped(t *testing.T) {
	e := &enc{}
	e.byte1(tSTRING).i16(9).str("future field")
	e.byte1(tI32).i16(1).i32(3)
	e.byte1(tSTOP)
	st, err := e.reader().readExtensionStatus()
	require.NoError(t, err)
	assert.Equal(t, int32(3), st.Code)
}

func TestReadExtensionStatus_WrongTypeForKnownIDSkipped(t *testing.T) {
	// Field id 1 with STRING type is not our i32 code — must be skipped, not
	// misparsed.
	e := (&enc{}).byte1(tSTRING).i16(1).str("not-a-code").byte1(tSTOP)
	st, err := e.reader().readExtensionStatus()
	require.NoError(t, err)
	assert.Equal(t, int32(0), st.Code)
}

func TestReadExtensionStatus_Truncated(t *testing.T) {
	e := (&enc{}).byte1(tI32).i16(1) // field header, no value
	_, err := e.reader().readExtensionStatus()
	require.Error(t, err)
}

// encodeRows writes list<map<string,string>> given rows.
func encodeRows(e *enc, rows []map[string]string, keysInOrder [][]string) *enc {
	e.byte1(tMAP).i32(int32(len(rows))) //#nosec G115 -- test row counts are tiny
	for i, row := range rows {
		e.byte1(tSTRING).byte1(tSTRING).i32(int32(len(row))) //#nosec G115 -- test rows are tiny
		for _, k := range keysInOrder[i] {
			e.str(k).str(row[k])
		}
	}
	return e
}

func TestReadRows_Empty(t *testing.T) {
	r := (&enc{}).byte1(tMAP).i32(0).reader()
	rows, err := r.readRows()
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestReadRows_TwoRows(t *testing.T) {
	e := encodeRows(&enc{},
		[]map[string]string{{"pid": "1", "name": "init"}, {"pid": "2", "name": "kthreadd"}},
		[][]string{{"pid", "name"}, {"pid", "name"}})
	rows, err := e.reader().readRows()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "init", rows[0]["name"])
	assert.Equal(t, "2", rows[1]["pid"])
}

func TestReadRows_EmptyValuesPreserved(t *testing.T) {
	e := encodeRows(&enc{},
		[]map[string]string{{"sha256": ""}},
		[][]string{{"sha256"}})
	rows, err := e.reader().readRows()
	require.NoError(t, err)
	v, ok := rows[0]["sha256"]
	assert.True(t, ok, "empty value must still be present in the row map")
	assert.Equal(t, "", v)
}

func TestReadRows_WrongElemTypeErrors(t *testing.T) {
	r := (&enc{}).byte1(tI32).i32(1).reader()
	_, err := r.readRows()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "want map")
}

func TestReadRows_NonStringPairsAreProtocolDrift(t *testing.T) {
	// ExtensionPluginResponse is map<string,string> by schema. A row of
	// map<i32,i32> means the protocol drifted — that must be a LOUD error,
	// not an empty row a caller would misread as a real result.
	e := (&enc{}).byte1(tMAP).i32(1)
	e.byte1(tI32).byte1(tI32).i32(1).i32(5).i32(6)
	_, err := e.reader().readRows()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "want (string,string)")
}

func TestReadRows_RowCountCapped(t *testing.T) {
	r := (&enc{}).byte1(tMAP).i32(maxThriftContainer + 1).reader()
	_, err := r.readRows()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestReadRows_TruncatedMidRow(t *testing.T) {
	e := (&enc{}).byte1(tMAP).i32(1).byte1(tSTRING).byte1(tSTRING).i32(2).str("k")
	_, err := e.reader().readRows()
	require.Error(t, err)
}

func TestReadApplicationException_MessageAndType(t *testing.T) {
	e := &enc{}
	e.byte1(tSTRING).i16(1).str("unknown method")
	e.byte1(tI32).i16(2).i32(1)
	e.byte1(tSTOP)
	err := e.reader().readApplicationException()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown method")
	assert.Contains(t, err.Error(), "type 1")
}

func TestReadApplicationException_EmptyStillErrors(t *testing.T) {
	r := (&enc{}).byte1(tSTOP).reader()
	err := r.readApplicationException()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown thrift application exception")
}

func TestReadApplicationException_ExtraFieldsSkipped(t *testing.T) {
	e := &enc{}
	e.byte1(tI64).i16(5).i64(1)
	e.byte1(tSTRING).i16(1).str("boom")
	e.byte1(tSTOP)
	err := e.reader().readApplicationException()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}
