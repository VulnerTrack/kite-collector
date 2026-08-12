package osquery

// Minimal Apache Thrift binary-protocol codec — just enough to call the two
// ExtensionManager methods a collector needs (`query`, `ping`) over osquery's
// extensions socket. Mirrors the docker source's philosophy: raw protocol,
// no vendor SDK. The full osquery-go client would pull the entire Thrift
// runtime into the supply chain for two RPCs.
//
// Wire format (strict binary, unframed — what osqueryd speaks on the socket):
//
//	message  := i32(0x80010000|type) string(name) i32(seqid) struct
//	struct   := { byte(ftype) i16(fid) value }* byte(0 /*STOP*/)
//	string   := i32(len) bytes
//	list     := byte(etype) i32(count) value*
//	map      := byte(ktype) byte(vtype) i32(count) (key value)*
//
// osquery.thrift, the parts used here:
//
//	struct ExtensionStatus  { 1: i32 code, 2: string message, 3: i64 uuid }
//	struct ExtensionResponse{ 1: ExtensionStatus status,
//	                          2: list<map<string,string>> response }
//	service ExtensionManager { ExtensionResponse query(1: string sql)
//	                           ExtensionStatus  ping() }

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Thrift type constants (TType).
const (
	tSTOP   = 0
	tBOOL   = 2
	tBYTE   = 3
	tDOUBLE = 4
	tI16    = 6
	tI32    = 8
	tI64    = 10
	tSTRING = 11
	tSTRUCT = 12
	tMAP    = 13
	tSET    = 14
	tLIST   = 15
)

// Thrift message types.
const (
	mCALL      = 1
	mREPLY     = 2
	mEXCEPTION = 3
)

// thriftVersion1 is the strict binary-protocol version marker.
const thriftVersion1 = 0x80010000

// Decode guards: a malformed or hostile peer must produce an error, not an
// out-of-memory. Sizes are far above anything a legitimate osqueryd emits.
const (
	maxThriftString    = 64 << 20 // 64 MiB per string
	maxThriftContainer = 4 << 20  // 4M elements per list/map
	maxSkipDepth       = 64       // nested-struct recursion cap
)

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

type thriftWriter struct {
	w *bufio.Writer
}

func newThriftWriter(w io.Writer) *thriftWriter {
	return &thriftWriter{w: bufio.NewWriter(w)}
}

func (t *thriftWriter) writeByte(v byte) { _ = t.w.WriteByte(v) }

func (t *thriftWriter) writeI16(v int16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v)) //#nosec G115 -- two's-complement wire encoding
	_, _ = t.w.Write(b[:])
}

func (t *thriftWriter) writeI32(v int32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v)) //#nosec G115 -- two's-complement wire encoding
	_, _ = t.w.Write(b[:])
}

func (t *thriftWriter) writeString(s string) {
	t.writeI32(int32(len(s))) //#nosec G115 -- SQL/method strings, nowhere near 2GiB
	_, _ = t.w.WriteString(s)
}

// writeMessageBegin emits the strict-protocol message header.
func (t *thriftWriter) writeMessageBegin(name string, typ int32, seqID int32) {
	t.writeI32(int32(uint32(thriftVersion1) | uint32(typ))) //#nosec G115 -- protocol version word sets the sign bit by design
	t.writeString(name)
	t.writeI32(seqID)
}

// writeFieldBegin emits a struct field header.
func (t *thriftWriter) writeFieldBegin(ftype byte, id int16) {
	t.writeByte(ftype)
	t.writeI16(id)
}

func (t *thriftWriter) writeFieldStop() { t.writeByte(tSTOP) }

func (t *thriftWriter) flush() error {
	if err := t.w.Flush(); err != nil {
		return fmt.Errorf("thrift: flush: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

type thriftReader struct {
	r *bufio.Reader
}

func newThriftReader(r io.Reader) *thriftReader {
	return &thriftReader{r: bufio.NewReader(r)}
}

func (t *thriftReader) readByte() (byte, error) {
	b, err := t.r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("thrift: read byte: %w", err)
	}
	return b, nil
}

func (t *thriftReader) readI16() (int16, error) {
	var b [2]byte
	if _, err := io.ReadFull(t.r, b[:]); err != nil {
		return 0, fmt.Errorf("thrift: read i16: %w", err)
	}
	return int16(binary.BigEndian.Uint16(b[:])), nil //#nosec G115 -- two's-complement wire decoding
}

func (t *thriftReader) readI32() (int32, error) {
	var b [4]byte
	if _, err := io.ReadFull(t.r, b[:]); err != nil {
		return 0, fmt.Errorf("thrift: read i32: %w", err)
	}
	return int32(binary.BigEndian.Uint32(b[:])), nil //#nosec G115 -- two's-complement wire decoding
}

func (t *thriftReader) readI64() (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(t.r, b[:]); err != nil {
		return 0, fmt.Errorf("thrift: read i64: %w", err)
	}
	return int64(binary.BigEndian.Uint64(b[:])), nil //#nosec G115 -- two's-complement wire decoding
}

func (t *thriftReader) readString() (string, error) {
	n, err := t.readI32()
	if err != nil {
		return "", err
	}
	if n < 0 || n > maxThriftString {
		return "", fmt.Errorf("thrift: string length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.r, buf); err != nil {
		return "", fmt.Errorf("thrift: read string body: %w", err)
	}
	return string(buf), nil
}

// readMessageBegin parses the reply header and returns (messageType, seqID).
func (t *thriftReader) readMessageBegin() (int32, int32, error) {
	head, err := t.readI32()
	if err != nil {
		return 0, 0, err
	}
	if uint32(head)&0xffff0000 != thriftVersion1 { //#nosec G115 -- reinterpreting the header word is the protocol
		return 0, 0, fmt.Errorf("thrift: bad protocol version 0x%08x", uint32(head))
	}
	typ := head & 0xff
	if _, nerr := t.readString(); nerr != nil { // method name (unused)
		return 0, 0, nerr
	}
	seq, err := t.readI32()
	if err != nil {
		return 0, 0, err
	}
	return typ, seq, nil
}

// readFieldBegin returns (fieldType, fieldID). fieldType tSTOP ends a struct.
func (t *thriftReader) readFieldBegin() (byte, int16, error) {
	ftype, err := t.readByte()
	if err != nil {
		return 0, 0, err
	}
	if ftype == tSTOP {
		return tSTOP, 0, nil
	}
	id, err := t.readI16()
	if err != nil {
		return 0, 0, err
	}
	return ftype, id, nil
}

// skip discards a value of the given type — required to stay compatible when
// osquery adds fields to its structs.
func (t *thriftReader) skip(ftype byte, depth int) error {
	if depth > maxSkipDepth {
		return fmt.Errorf("thrift: skip recursion deeper than %d", maxSkipDepth)
	}
	switch ftype {
	case tBOOL, tBYTE:
		_, err := t.readByte()
		return err
	case tI16:
		_, err := t.readI16()
		return err
	case tI32:
		_, err := t.readI32()
		return err
	case tI64, tDOUBLE:
		_, err := t.readI64()
		return err
	case tSTRING:
		_, err := t.readString()
		return err
	case tSTRUCT:
		for {
			ft, _, err := t.readFieldBegin()
			if err != nil {
				return err
			}
			if ft == tSTOP {
				return nil
			}
			if err := t.skip(ft, depth+1); err != nil {
				return err
			}
		}
	case tMAP:
		kt, err := t.readByte()
		if err != nil {
			return err
		}
		vt, err := t.readByte()
		if err != nil {
			return err
		}
		n, err := t.readI32()
		if err != nil {
			return err
		}
		if n < 0 || n > maxThriftContainer {
			return fmt.Errorf("thrift: map size %d out of range", n)
		}
		for i := int32(0); i < n; i++ {
			if err := t.skip(kt, depth+1); err != nil {
				return err
			}
			if err := t.skip(vt, depth+1); err != nil {
				return err
			}
		}
		return nil
	case tLIST, tSET:
		et, err := t.readByte()
		if err != nil {
			return err
		}
		n, err := t.readI32()
		if err != nil {
			return err
		}
		if n < 0 || n > maxThriftContainer {
			return fmt.Errorf("thrift: list size %d out of range", n)
		}
		for i := int32(0); i < n; i++ {
			if err := t.skip(et, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("thrift: cannot skip unknown type %d", ftype)
	}
}

// ---------------------------------------------------------------------------
// osquery extension structs
// ---------------------------------------------------------------------------

// extensionStatus mirrors osquery.thrift's ExtensionStatus.
type extensionStatus struct {
	Message string
	Code    int32
	UUID    int64
}

// readExtensionStatus decodes an ExtensionStatus struct.
func (t *thriftReader) readExtensionStatus() (extensionStatus, error) {
	var st extensionStatus
	for {
		ftype, id, err := t.readFieldBegin()
		if err != nil {
			return st, err
		}
		if ftype == tSTOP {
			return st, nil
		}
		switch {
		case id == 1 && ftype == tI32:
			st.Code, err = t.readI32()
		case id == 2 && ftype == tSTRING:
			st.Message, err = t.readString()
		case id == 3 && ftype == tI64:
			st.UUID, err = t.readI64()
		default:
			err = t.skip(ftype, 0)
		}
		if err != nil {
			return st, err
		}
	}
}

// readRows decodes ExtensionPluginResponse: list<map<string,string>>.
func (t *thriftReader) readRows() ([]map[string]string, error) {
	et, err := t.readByte()
	if err != nil {
		return nil, err
	}
	if et != tMAP {
		return nil, fmt.Errorf("thrift: response list of type %d, want map", et)
	}
	n, err := t.readI32()
	if err != nil {
		return nil, err
	}
	if n < 0 || n > maxThriftContainer {
		return nil, fmt.Errorf("thrift: row count %d out of range", n)
	}
	rows := make([]map[string]string, 0, min(int(n), 4096))
	for i := int32(0); i < n; i++ {
		kt, err := t.readByte()
		if err != nil {
			return nil, err
		}
		vt, err := t.readByte()
		if err != nil {
			return nil, err
		}
		pairs, err := t.readI32()
		if err != nil {
			return nil, err
		}
		if pairs < 0 || pairs > maxThriftContainer {
			return nil, fmt.Errorf("thrift: row size %d out of range", pairs)
		}
		if kt != tSTRING || vt != tSTRING {
			// Not the map<string,string> we expect — skip defensively.
			for j := int32(0); j < pairs; j++ {
				if err := t.skip(kt, 0); err != nil {
					return nil, err
				}
				if err := t.skip(vt, 0); err != nil {
					return nil, err
				}
			}
			rows = append(rows, map[string]string{})
			continue
		}
		row := make(map[string]string, pairs)
		for j := int32(0); j < pairs; j++ {
			k, err := t.readString()
			if err != nil {
				return nil, err
			}
			v, err := t.readString()
			if err != nil {
				return nil, err
			}
			row[k] = v
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// readApplicationException decodes a TApplicationException reply into an error.
func (t *thriftReader) readApplicationException() error {
	msg := "unknown thrift application exception"
	var code int32
	for {
		ftype, id, err := t.readFieldBegin()
		if err != nil {
			return fmt.Errorf("thrift: decoding exception: %w", err)
		}
		if ftype == tSTOP {
			break
		}
		switch {
		case id == 1 && ftype == tSTRING:
			if msg, err = t.readString(); err != nil {
				return err
			}
		case id == 2 && ftype == tI32:
			if code, err = t.readI32(); err != nil {
				return err
			}
		default:
			if err := t.skip(ftype, 0); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("thrift: application exception (type %d): %s", code, msg)
}
