package snmp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Response packet construction helpers (test-side SNMP agent encoding)
// -------------------------------------------------------------------------

// buildGetResponsePacket assembles a well-formed SNMPv2c GetResponse whose
// single varbind carries the supplied raw value TLV.
func buildGetResponsePacket(valueTLV []byte) []byte {
	varbind := berSequence(append(berOID(encodeOID(oidSysName)), valueTLV...))
	varbindList := berSequence(varbind)

	pduContent := berInteger(1) // request-id (parseGetResponse skips it)
	pduContent = append(pduContent, berInteger(0)...)
	pduContent = append(pduContent, berInteger(0)...)
	pduContent = append(pduContent, varbindList...)
	pdu := berTagLengthValue(tagGetResponse, pduContent)

	msg := berInteger(1)
	msg = append(msg, berOctetString([]byte("public"))...)
	msg = append(msg, pdu...)
	return berSequence(msg)
}

// buildResponseWithPDUTag builds an otherwise valid response whose PDU
// carries an arbitrary tag, so the GetResponse tag check is observable.
func buildResponseWithPDUTag(pduTag byte, pduContent []byte) []byte {
	msg := berInteger(1)
	msg = append(msg, berOctetString([]byte("public"))...)
	msg = append(msg, berTagLengthValue(pduTag, pduContent)...)
	return berSequence(msg)
}

// -------------------------------------------------------------------------
// parseGetResponse — value decoding
// -------------------------------------------------------------------------

func TestParseGetResponse_OctetString(t *testing.T) {
	got, err := parseGetResponse(buildGetResponsePacket(berOctetString([]byte("core-sw-01"))))
	require.NoError(t, err)
	assert.Equal(t, "core-sw-01", got)
}

func TestParseGetResponse_Integer(t *testing.T) {
	got, err := parseGetResponse(buildGetResponsePacket(berInteger(42)))
	require.NoError(t, err)
	assert.Equal(t, "42", got)
}

func TestParseGetResponse_NegativeInteger(t *testing.T) {
	got, err := parseGetResponse(buildGetResponsePacket(berInteger(-1)))
	require.NoError(t, err)
	assert.Equal(t, "-1", got)
}

func TestParseGetResponse_TimeTicks(t *testing.T) {
	// 100000 ticks = 0x0186a0.
	ticks := berTagLengthValue(tagTimeTicks, []byte{0x01, 0x86, 0xa0})
	got, err := parseGetResponse(buildGetResponsePacket(ticks))
	require.NoError(t, err)
	assert.Equal(t, "100000", got)
}

func TestParseGetResponse_NoSuchObjectVariants(t *testing.T) {
	for _, tag := range []byte{tagNoSuchObject, tagNoSuchInst, tagEndOfMIBView} {
		_, err := parseGetResponse(buildGetResponsePacket(berTagLengthValue(tag, nil)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such object")
	}
}

func TestParseGetResponse_UnknownTagFallsBackToHex(t *testing.T) {
	got, err := parseGetResponse(buildGetResponsePacket(berTagLengthValue(0x41, []byte{0xde, 0xad})))
	require.NoError(t, err)
	assert.Equal(t, "0xdead", got)
}

// -------------------------------------------------------------------------
// parseGetResponse — malformed packet error paths
// -------------------------------------------------------------------------

func TestParseGetResponse_MalformedPackets(t *testing.T) {
	threeInts := berInteger(1)
	threeInts = append(threeInts, berInteger(0)...)
	threeInts = append(threeInts, berInteger(0)...)

	withVarbindList := func(vbl []byte) []byte {
		return buildResponseWithPDUTag(tagGetResponse, append(append([]byte{}, threeInts...), vbl...))
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "truncated outer", data: []byte{0x30}, wantErr: "parse outer"},
		{name: "truncated version", data: berSequence([]byte{0x02}), wantErr: "parse version"},
		{
			name:    "missing community",
			data:    berSequence(berInteger(1)),
			wantErr: "parse community",
		},
		{
			name: "truncated PDU",
			data: berSequence(append(append(berInteger(1),
				berOctetString([]byte("public"))...), 0xa2)),
			wantErr: "parse PDU",
		},
		{
			name:    "wrong PDU tag",
			data:    buildResponseWithPDUTag(tagGetRequest, threeInts),
			wantErr: "expected GetResponse (0xa2), got 0xa0",
		},
		{
			name:    "missing request-id",
			data:    buildResponseWithPDUTag(tagGetResponse, nil),
			wantErr: "parse request-id",
		},
		{
			name:    "missing error-status",
			data:    buildResponseWithPDUTag(tagGetResponse, berInteger(1)),
			wantErr: "parse error-status",
		},
		{
			name:    "missing error-index",
			data:    buildResponseWithPDUTag(tagGetResponse, append(berInteger(1), berInteger(0)...)),
			wantErr: "parse error-index",
		},
		{
			name:    "missing varbind list",
			data:    buildResponseWithPDUTag(tagGetResponse, threeInts),
			wantErr: "parse varbind list",
		},
		{
			name:    "empty varbind list",
			data:    withVarbindList(berSequence(nil)),
			wantErr: "parse varbind",
		},
		{
			name:    "empty varbind",
			data:    withVarbindList(berSequence(berSequence(nil))),
			wantErr: "parse OID in varbind",
		},
		{
			name:    "varbind without value",
			data:    withVarbindList(berSequence(berSequence(berOID(encodeOID(oidSysName))))),
			wantErr: "parse value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseGetResponse(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// -------------------------------------------------------------------------
// BER decoding edge cases
// -------------------------------------------------------------------------

func TestBerParse_LongFormLength(t *testing.T) {
	content := make([]byte, 200)
	for i := range content {
		content[i] = byte(i)
	}
	data := berOctetString(content)
	// Long form header: tag, 0x81 (one length byte), 200.
	require.Equal(t, []byte{tagOctetString, 0x81, 200}, data[:3])

	tag, got, err := berParse(data)
	require.NoError(t, err)
	assert.Equal(t, tagOctetString, tag)
	assert.Equal(t, content, got)
}

func TestBerParse_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: []byte{0x04}, wantErr: "data too short"},
		{name: "length bytes overflow", data: []byte{0x30, 0x84, 0x00, 0x00}, wantErr: "length bytes overflow"},
		{name: "content overflow", data: []byte{0x04, 0x05, 0x61}, wantErr: "content overflow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := berParse(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBerParseNext_LongFormLength(t *testing.T) {
	content := make([]byte, 130)
	first := berOctetString(content)
	second := berInteger(7)

	elem, rest, err := berParseNext(append(append([]byte{}, first...), second...))
	require.NoError(t, err)
	assert.Equal(t, first, elem)
	assert.Equal(t, second, rest)
}

func TestBerParseNext_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: []byte{0x04}, wantErr: "data too short"},
		{name: "length overflow", data: []byte{0x30, 0x83, 0x01}, wantErr: "length overflow"},
		{name: "element overflow", data: []byte{0x04, 0x02, 0x61}, wantErr: "element overflow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := berParseNext(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBerInteger_NegativeValues(t *testing.T) {
	assert.Equal(t, []byte{tagInteger, 0x01, 0xff}, berInteger(-1))
	assert.Equal(t, []byte{tagInteger, 0x02, 0xff, 0x00}, berInteger(-256))
}

func TestEncodeOID_TooFewComponents(t *testing.T) {
	assert.Nil(t, encodeOID("1"))
}

// -------------------------------------------------------------------------
// Config coercion helpers
// -------------------------------------------------------------------------

func TestToString(t *testing.T) {
	assert.Equal(t, "x", toString("x"))
	assert.Equal(t, "", toString(nil))
	assert.Equal(t, "", toString(42))
}

func TestToStringSlice(t *testing.T) {
	assert.Nil(t, toStringSlice(nil))
	assert.Equal(t, []string{"a", "b"}, toStringSlice([]string{"a", "b"}))
	assert.Equal(t, []string{"a", "b"}, toStringSlice([]any{"a", 1, "b", nil}))
	assert.Nil(t, toStringSlice("not-a-slice"))
	assert.Empty(t, toStringSlice([]any{}))
}

// -------------------------------------------------------------------------
// snmpGet over UDP loopback with a fake responder
// -------------------------------------------------------------------------

// startUDPResponder binds an ephemeral UDP port on 127.0.0.1 and answers
// every datagram through handler (nil reply = stay silent). It returns the
// listener address and a channel carrying each raw request received.
func startUDPResponder(t *testing.T, handler func(req []byte) []byte) (string, <-chan []byte) {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	requests := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			requests <- req
			if resp := handler(req); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String(), requests
}

func TestSnmpGet_HappyPath(t *testing.T) {
	target, requests := startUDPResponder(t, func([]byte) []byte {
		return buildGetResponsePacket(berOctetString([]byte("edge-router-7")))
	})

	got, err := snmpGet(context.Background(), target, "sec-comm", oidSysName, time.Second)
	require.NoError(t, err)
	assert.Equal(t, "edge-router-7", got)

	// The request on the wire must be a v2c GetRequest carrying the
	// configured community and the requested OID.
	req := <-requests
	_, content, err := berParse(req)
	require.NoError(t, err)
	versionElem, rest, err := berParseNext(content)
	require.NoError(t, err)
	_, versionData, err := berParse(versionElem)
	require.NoError(t, err)
	assert.Equal(t, int64(1), berDecodeInteger(versionData), "SNMPv2c version marker")
	commElem, rest, err := berParseNext(rest)
	require.NoError(t, err)
	commTag, commData, err := berParse(commElem)
	require.NoError(t, err)
	assert.Equal(t, tagOctetString, commTag)
	assert.Equal(t, "sec-comm", string(commData))
	pduTag, _, err := berParse(rest)
	require.NoError(t, err)
	assert.Equal(t, tagGetRequest, pduTag)
}

func TestSnmpGet_MalformedResponseSurfacesParseError(t *testing.T) {
	target, _ := startUDPResponder(t, func([]byte) []byte {
		return []byte{0x30} // truncated BER
	})

	_, err := snmpGet(context.Background(), target, "public", oidSysName, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse outer")
}

func TestSnmpGet_TimeoutWhenAgentSilent(t *testing.T) {
	target, _ := startUDPResponder(t, func([]byte) []byte { return nil })

	start := time.Now()
	_, err := snmpGet(context.Background(), target, "public", oidSysName, 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read snmp response")
	assert.Less(t, time.Since(start), 5*time.Second, "timeout must be honored")
}

func TestSnmpGet_DialErrorOnInvalidTarget(t *testing.T) {
	_, err := snmpGet(context.Background(), "127.0.0.1:99999", "public", oidSysName, 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial snmp")
}

// -------------------------------------------------------------------------
// Discover — loopback probing paths
// -------------------------------------------------------------------------

func TestSNMP_Discover_LoopbackNoResponderFindsNothing(t *testing.T) {
	s := New()
	machines, err := s.Discover(context.Background(), map[string]any{
		"community":      "private",
		"scope":          []string{"127.0.0.1"},
		"timeout":        "50ms",
		"max_concurrent": 2,
	})
	require.NoError(t, err)
	assert.Empty(t, machines, "closed loopback port must yield no machines")
}

func TestSNMP_Discover_EnvCommunityAndAnyScope(t *testing.T) {
	t.Setenv("KITE_SNMP_COMMUNITY", "from-env")
	s := New()
	machines, err := s.Discover(context.Background(), map[string]any{
		"scope":   []any{"127.0.0.1"},
		"timeout": "not-a-duration", // falls back to the default timeout
	})
	require.NoError(t, err)
	assert.Empty(t, machines)
}

func TestSNMP_Discover_InvalidCIDRSurfacesError(t *testing.T) {
	s := New()
	_, err := s.Discover(context.Background(), map[string]any{
		"scope": []string{"10.0.0.0/99"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expand targets")
}

func TestSNMP_Discover_CancelledContextStopsProbing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New()
	machines, err := s.Discover(ctx, map[string]any{
		"scope":          []string{"127.0.0.0/27"}, // 32 loopback addresses
		"timeout":        "50ms",
		"max_concurrent": 1,
	})
	require.NoError(t, err)
	assert.Empty(t, machines)
}
