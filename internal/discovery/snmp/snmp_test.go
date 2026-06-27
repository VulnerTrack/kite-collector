package snmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -------------------------------------------------------------------------
// BER encoding tests
// -------------------------------------------------------------------------

func TestEncodeOID(t *testing.T) {
	// sysDescr.0 = 1.3.6.1.2.1.1.1.0
	// First two: 40*1+3 = 43
	encoded := encodeOID("1.3.6.1.2.1.1.1.0")
	require.NotEmpty(t, encoded)
	assert.Equal(t, byte(43), encoded[0], "first byte = 40*1 + 3")
	assert.Equal(t, byte(6), encoded[1])
	assert.Equal(t, byte(1), encoded[2])
	assert.Equal(t, byte(2), encoded[3])
	assert.Equal(t, byte(1), encoded[4])
	assert.Equal(t, byte(1), encoded[5])
	assert.Equal(t, byte(1), encoded[6])
	assert.Equal(t, byte(0), encoded[7])
}

func TestEncodeOIDComponent_Small(t *testing.T) {
	result := encodeOIDComponent(127)
	assert.Equal(t, []byte{127}, result)
}

func TestEncodeOIDComponent_Large(t *testing.T) {
	result := encodeOIDComponent(128)
	assert.Equal(t, []byte{0x81, 0x00}, result)

	result = encodeOIDComponent(256)
	assert.Equal(t, []byte{0x82, 0x00}, result)
}

func TestBerInteger(t *testing.T) {
	// Encode 1
	data := berInteger(1)
	assert.Equal(t, byte(tagInteger), data[0])
	assert.Equal(t, byte(1), data[1]) // length
	assert.Equal(t, byte(1), data[2]) // value

	// Encode 0
	data = berInteger(0)
	assert.Equal(t, byte(tagInteger), data[0])
	assert.Equal(t, byte(1), data[1])
	assert.Equal(t, byte(0), data[2])
}

func TestBerOctetString(t *testing.T) {
	data := berOctetString([]byte("public"))
	assert.Equal(t, byte(tagOctetString), data[0])
	assert.Equal(t, byte(6), data[1]) // length
	assert.Equal(t, "public", string(data[2:]))
}

func TestBerLength(t *testing.T) {
	// Short form.
	assert.Equal(t, []byte{42}, berLength(42))
	assert.Equal(t, []byte{0}, berLength(0))
	assert.Equal(t, []byte{127}, berLength(127))

	// Long form.
	long := berLength(256)
	assert.Equal(t, byte(0x82), long[0]) // 0x80 | 2 bytes
}

func TestBerDecodeInteger(t *testing.T) {
	assert.Equal(t, int64(1), berDecodeInteger([]byte{1}))
	assert.Equal(t, int64(256), berDecodeInteger([]byte{1, 0}))
	assert.Equal(t, int64(-1), berDecodeInteger([]byte{0xff}))
	assert.Equal(t, int64(0), berDecodeInteger(nil))
}

func TestBerDecodeUnsigned(t *testing.T) {
	assert.Equal(t, uint64(256), berDecodeUnsigned([]byte{1, 0}))
	assert.Equal(t, uint64(0), berDecodeUnsigned(nil))
}

func TestBerParse(t *testing.T) {
	// Encode a simple OCTET STRING "hi".
	data := berOctetString([]byte("hi"))
	tag, content, err := berParse(data)
	require.NoError(t, err)
	assert.Equal(t, tagOctetString, tag)
	assert.Equal(t, "hi", string(content))
}

func TestBerParseNext(t *testing.T) {
	// Two TLV elements back to back.
	a := berInteger(42)
	b := berOctetString([]byte("x"))
	combined := append(a, b...)

	elem, rest, err := berParseNext(combined)
	require.NoError(t, err)
	assert.Equal(t, a, elem)
	assert.Equal(t, b, rest)
}

func TestBuildGetRequest(t *testing.T) {
	pdu := buildGetRequest("public", "1.3.6.1.2.1.1.1.0", 12345)
	require.NotEmpty(t, pdu)

	// Should start with SEQUENCE tag.
	assert.Equal(t, tagSequence, pdu[0])

	// Parse outer sequence.
	_, content, err := berParse(pdu)
	require.NoError(t, err)

	// First element: version INTEGER 1.
	versionElem, rest, err := berParseNext(content)
	require.NoError(t, err)
	vTag, vData, err := berParse(versionElem)
	require.NoError(t, err)
	assert.Equal(t, tagInteger, vTag)
	assert.Equal(t, int64(1), berDecodeInteger(vData))

	// Second element: community OCTET STRING "public".
	commElem, rest, err := berParseNext(rest)
	require.NoError(t, err)
	cTag, cData, err := berParse(commElem)
	require.NoError(t, err)
	assert.Equal(t, tagOctetString, cTag)
	assert.Equal(t, "public", string(cData))

	// Third element: GetRequest PDU.
	pduTag, _, err := berParse(rest)
	require.NoError(t, err)
	assert.Equal(t, tagGetRequest, pduTag)
}

// -------------------------------------------------------------------------
// Network helper tests
// -------------------------------------------------------------------------

func TestExpandCIDRs_SingleIP(t *testing.T) {
	ips, err := expandCIDRs([]string{"192.168.1.1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, ips)
}

func TestExpandCIDRs_CIDR(t *testing.T) {
	ips, err := expandCIDRs([]string{"10.0.0.0/30"})
	require.NoError(t, err)
	assert.Len(t, ips, 4) // /30 = 4 IPs (including network and broadcast)
}

func TestExpandCIDRs_Invalid(t *testing.T) {
	_, err := expandCIDRs([]string{"not-a-cidr/99"})
	require.Error(t, err)
}

// -------------------------------------------------------------------------
// Classification tests
// -------------------------------------------------------------------------

func TestClassifyDevice(t *testing.T) {
	tests := []struct {
		desc   string
		expect model.AssetType
	}{
		{"Cisco IOS Software, C2960 Switch", model.AssetTypeNetworkDevice},
		{"APC Smart-UPS 1500 UPS", model.AssetTypeAppliance},
		{"Linux hostname 5.15.0", model.AssetTypeServer},
		{"Windows Server 2022", model.AssetTypeServer},
		{"Unknown Device", model.AssetTypeNetworkDevice},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert.Equal(t, tt.expect, classifyDevice(tt.desc))
		})
	}
}

func TestExtractOSFamily(t *testing.T) {
	assert.Equal(t, "linux", extractOSFamily("Linux hostname 5.15"))
	assert.Equal(t, "windows", extractOSFamily("Hardware: x86 Windows Server"))
	assert.Equal(t, "cisco_ios", extractOSFamily("Cisco IOS Software"))
	assert.Equal(t, "junos", extractOSFamily("Juniper Networks JunOS"))
	assert.Equal(t, "", extractOSFamily("Unknown"))
}

// -------------------------------------------------------------------------
// Source interface tests
// -------------------------------------------------------------------------

func TestSNMP_Name(t *testing.T) {
	s := New()
	assert.Equal(t, "snmp", s.Name())
}

func TestSNMP_Discover_MissingScope(t *testing.T) {
	s := New()
	_, err := s.Discover(t.Context(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope")
}
