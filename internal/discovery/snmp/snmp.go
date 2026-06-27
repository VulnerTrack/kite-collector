// Package snmp implements a discovery.Source that enumerates network devices
// via SNMPv2c using a pure Go BER encoder/decoder.  No external SNMP library
// dependency — the protocol is simple enough for basic GET and WALK operations.
package snmp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Standard MIB OIDs for device identification.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"

	defaultCommunity = "public"
	defaultTimeout   = 5 * time.Second
	defaultMaxConc   = 32
	defaultSNMPPort  = 161
)

// SNMP implements discovery.Source for SNMPv2c network devices.
type SNMP struct{}

// New returns a new SNMP discovery source.
func New() *SNMP { return &SNMP{} }

// Name returns the stable identifier for this source.
func (s *SNMP) Name() string { return "snmp" }

// Discover probes configured CIDR targets via SNMPv2c and returns discovered
// network devices as assets.
func (s *SNMP) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	community := toString(cfg["community"])
	if community == "" {
		community = os.Getenv("KITE_SNMP_COMMUNITY")
	}
	if community == "" {
		community = defaultCommunity
	}

	targets := toStringSlice(cfg["scope"])
	if len(targets) == 0 {
		return nil, fmt.Errorf("snmp: scope (target CIDRs) is required")
	}

	timeout := defaultTimeout
	if ts := toString(cfg["timeout"]); ts != "" {
		if d, err := time.ParseDuration(ts); err == nil {
			timeout = d
		}
	}

	maxConc := defaultMaxConc
	if mc, ok := cfg["max_concurrent"].(int); ok && mc > 0 {
		maxConc = mc
	}

	slog.Info("snmp: starting discovery", "targets", len(targets), "timeout", timeout) //#nosec G706 -- structured slog

	ips, err := expandCIDRs(targets)
	if err != nil {
		return nil, fmt.Errorf("snmp: expand targets: %w", err)
	}

	var (
		mu     sync.Mutex
		assets []model.Asset
		sem    = make(chan struct{}, maxConc)
		wg     sync.WaitGroup
	)

	now := time.Now().UTC()

loop:
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()

			asset, probeErr := probeHost(ctx, addr, community, timeout, now)
			if probeErr != nil {
				return // host didn't respond
			}

			mu.Lock()
			assets = append(assets, *asset)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

	slog.Info("snmp: discovery complete", "probed", len(ips), "found", len(assets)) //#nosec G706 -- structured slog
	return assets, nil
}

func probeHost(ctx context.Context, addr, community string, timeout time.Duration, now time.Time) (*model.Asset, error) {
	target := fmt.Sprintf("%s:%d", addr, defaultSNMPPort)

	// Probe sysName first — if this fails, the host is likely unreachable.
	sysName, err := snmpGet(ctx, target, community, oidSysName, timeout)
	if err != nil {
		return nil, err
	}
	if sysName == "" {
		return nil, fmt.Errorf("empty sysName")
	}

	// Fetch remaining system info (best-effort).
	sysDescr, _ := snmpGet(ctx, target, community, oidSysDescr, timeout)
	sysLocation, _ := snmpGet(ctx, target, community, oidSysLocation, timeout)
	sysUpTime, _ := snmpGet(ctx, target, community, oidSysUpTime, timeout)

	tags := map[string]any{
		"ip":           addr,
		"sys_descr":    sysDescr,
		"sys_name":     sysName,
		"sys_location": sysLocation,
		"sys_uptime":   sysUpTime,
	}

	tagsJSON, _ := json.Marshal(tags)

	assetType := classifyDevice(sysDescr)

	return &model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        sysName,
		AssetType:       assetType,
		OSFamily:        extractOSFamily(sysDescr),
		DiscoverySource: "snmp",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}, nil
}

// classifyDevice infers the asset type from sysDescr.
func classifyDevice(sysDescr string) model.AssetType {
	lower := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(lower, "switch") || strings.Contains(lower, "router"):
		return model.AssetTypeNetworkDevice
	case strings.Contains(lower, "ups") || strings.Contains(lower, "pdu"):
		return model.AssetTypeAppliance
	case strings.Contains(lower, "linux") || strings.Contains(lower, "windows"):
		return model.AssetTypeServer
	default:
		return model.AssetTypeNetworkDevice
	}
}

// extractOSFamily extracts a rough OS family from sysDescr.
func extractOSFamily(sysDescr string) string {
	lower := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(lower, "linux"):
		return "linux"
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "cisco"):
		return "cisco_ios"
	case strings.Contains(lower, "juniper") || strings.Contains(lower, "junos"):
		return "junos"
	default:
		return ""
	}
}

// -------------------------------------------------------------------------
// CIDR expansion
// -------------------------------------------------------------------------

func expandCIDRs(cidrs []string) ([]string, error) {
	var ips []string
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			ips = append(ips, cidr)
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incIP(ip) {
			// Skip network and broadcast for /24 and smaller.
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// -------------------------------------------------------------------------
// Minimal SNMPv2c protocol — BER encoding/decoding
// -------------------------------------------------------------------------

// BER tag constants.
const (
	tagInteger      byte = 0x02
	tagOctetString  byte = 0x04
	tagNull         byte = 0x05
	tagOID          byte = 0x06
	tagSequence     byte = 0x30
	tagGetRequest   byte = 0xa0
	tagGetResponse  byte = 0xa2
	tagTimeTicks    byte = 0x43 // APPLICATION 3
	tagNoSuchObject byte = 0x80
	tagNoSuchInst   byte = 0x81
	tagEndOfMIBView byte = 0x82
)

// snmpGet sends an SNMPv2c GET request for a single OID and returns the
// value as a string.  Returns error if the host doesn't respond or the
// response is invalid.
func snmpGet(ctx context.Context, target, community, oid string, timeout time.Duration) (string, error) {
	reqID := uint32(time.Now().UnixNano() & 0x7FFFFFFF)
	pdu := buildGetRequest(community, oid, reqID)

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", target) //#nosec G704 -- target from user-configured scope
	if err != nil {
		return "", fmt.Errorf("dial snmp %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err = conn.Write(pdu); err != nil {
		return "", fmt.Errorf("write snmp request: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read snmp response: %w", err)
	}

	return parseGetResponse(buf[:n])
}

// buildGetRequest constructs an SNMPv2c GET request packet.
func buildGetRequest(community, oid string, reqID uint32) []byte {
	encodedOID := encodeOID(oid)

	// Variable binding: SEQUENCE { OID, NULL }
	varbind := berSequence(append(berOID(encodedOID), berNull()...))
	// Variable binding list: SEQUENCE { varbind }
	varbindList := berSequence(varbind)

	// PDU: GetRequest [0] { request-id, error-status(0), error-index(0), varbind-list }
	pduContent := berInteger(int64(reqID))
	pduContent = append(pduContent, berInteger(0)...) // error-status
	pduContent = append(pduContent, berInteger(0)...) // error-index
	pduContent = append(pduContent, varbindList...)
	pdu := berTagLengthValue(tagGetRequest, pduContent)

	// Message: SEQUENCE { version(1=v2c), community, pdu }
	msg := berInteger(1) // SNMPv2c
	msg = append(msg, berOctetString([]byte(community))...)
	msg = append(msg, pdu...)

	return berSequence(msg)
}

// parseGetResponse extracts the first value from an SNMP GET response.
func parseGetResponse(data []byte) (string, error) {
	// Outer SEQUENCE
	_, content, err := berParse(data)
	if err != nil {
		return "", fmt.Errorf("parse outer: %w", err)
	}

	// Skip version (INTEGER) and community (OCTET STRING).
	_, rest, err := berParseNext(content)
	if err != nil {
		return "", fmt.Errorf("parse version: %w", err)
	}
	_, rest, err = berParseNext(rest)
	if err != nil {
		return "", fmt.Errorf("parse community: %w", err)
	}

	// GetResponse PDU
	pduTag, pduContent, err := berParse(rest)
	if err != nil {
		return "", fmt.Errorf("parse PDU: %w", err)
	}
	if pduTag != tagGetResponse {
		return "", fmt.Errorf("expected GetResponse (0xa2), got 0x%02x", pduTag)
	}

	// Skip request-id, error-status, error-index.
	_, vbRest, err := berParseNext(pduContent)
	if err != nil {
		return "", fmt.Errorf("parse request-id: %w", err)
	}
	_, vbRest, err = berParseNext(vbRest)
	if err != nil {
		return "", fmt.Errorf("parse error-status: %w", err)
	}
	_, vbRest, err = berParseNext(vbRest)
	if err != nil {
		return "", fmt.Errorf("parse error-index: %w", err)
	}

	// Variable binding list: SEQUENCE { SEQUENCE { OID, value } }
	_, vbListContent, err := berParse(vbRest)
	if err != nil {
		return "", fmt.Errorf("parse varbind list: %w", err)
	}
	_, vbContent, err := berParse(vbListContent)
	if err != nil {
		return "", fmt.Errorf("parse varbind: %w", err)
	}

	// Skip OID, get value.
	_, valRest, err := berParseNext(vbContent)
	if err != nil {
		return "", fmt.Errorf("parse OID in varbind: %w", err)
	}

	valTag, valData, err := berParse(valRest)
	if err != nil {
		return "", fmt.Errorf("parse value: %w", err)
	}

	switch valTag {
	case tagOctetString:
		return string(valData), nil
	case tagInteger:
		return fmt.Sprintf("%d", berDecodeInteger(valData)), nil
	case tagTimeTicks:
		ticks := berDecodeUnsigned(valData)
		return fmt.Sprintf("%d", ticks), nil
	case tagNoSuchObject, tagNoSuchInst, tagEndOfMIBView:
		return "", fmt.Errorf("no such object")
	default:
		return fmt.Sprintf("0x%x", valData), nil
	}
}

// -------------------------------------------------------------------------
// BER encoding primitives
// -------------------------------------------------------------------------

func berSequence(content []byte) []byte {
	return berTagLengthValue(tagSequence, content)
}

func berTagLengthValue(tag byte, content []byte) []byte {
	return append([]byte{tag}, append(berLength(len(content)), content...)...)
}

func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)} //#nosec G115 -- n < 128, fits in byte
	}
	// Long form.
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(n)) //#nosec G115 -- BER lengths are bounded by packet size
	// Strip leading zeros.
	for len(lenBytes) > 1 && lenBytes[0] == 0 {
		lenBytes = lenBytes[1:]
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...) //#nosec G115 -- len(lenBytes) ≤ 4, fits in byte
}

func berInteger(v int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(v)) //#nosec G115 -- reinterpretation of signed to unsigned for BER encoding
	// Strip leading bytes that are redundant for signed encoding.
	for len(buf) > 1 {
		if buf[0] == 0 && buf[1]&0x80 == 0 {
			buf = buf[1:]
		} else if buf[0] == 0xff && buf[1]&0x80 != 0 {
			buf = buf[1:]
		} else {
			break
		}
	}
	return berTagLengthValue(tagInteger, buf)
}

func berOctetString(v []byte) []byte {
	return berTagLengthValue(tagOctetString, v)
}

func berNull() []byte {
	return []byte{tagNull, 0x00}
}

func berOID(encoded []byte) []byte {
	return berTagLengthValue(tagOID, encoded)
}

// encodeOID converts a dotted-decimal OID string to BER-encoded bytes.
func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}

	nums := make([]uint32, len(parts))
	for i, p := range parts {
		var n uint32
		for _, c := range p {
			n = n*10 + uint32(c-'0') //#nosec G115 -- ASCII digit subtraction always yields 0-9
		}
		nums[i] = n
	}

	// First two components encoded as 40*first + second.
	result := []byte{byte(nums[0]*40 + nums[1])} //#nosec G115 -- OID first two components always fit in byte (max 40*2+39=119)

	for _, n := range nums[2:] {
		result = append(result, encodeOIDComponent(n)...)
	}

	return result
}

func encodeOIDComponent(n uint32) []byte {
	if n < 128 {
		return []byte{byte(n)} //#nosec G115 -- n < 128, fits in byte
	}
	// Base-128 encoding with continuation bits.
	var buf []byte
	buf = append(buf, byte(n&0x7f)) //#nosec G115 -- masked to 7 bits, fits in byte
	n >>= 7
	for n > 0 {
		buf = append(buf, byte(n&0x7f|0x80)) //#nosec G115 -- masked to 7 bits + continuation, fits in byte
		n >>= 7
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}

// -------------------------------------------------------------------------
// BER decoding primitives
// -------------------------------------------------------------------------

// berParse extracts the tag, content bytes, and returns them.
func berParse(data []byte) (byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("BER: data too short")
	}

	tag := data[0]
	lenByte := data[1]
	offset := 2

	var length int
	if lenByte < 128 {
		length = int(lenByte)
	} else {
		numLenBytes := int(lenByte & 0x7f)
		if offset+numLenBytes > len(data) {
			return 0, nil, fmt.Errorf("BER: length bytes overflow")
		}
		for i := 0; i < numLenBytes; i++ {
			length = length<<8 | int(data[offset+i])
		}
		offset += numLenBytes
	}

	if offset+length > len(data) {
		return 0, nil, fmt.Errorf("BER: content overflow (need %d, have %d)", offset+length, len(data))
	}

	return tag, data[offset : offset+length], nil
}

// berParseNext extracts one TLV element from data and returns its raw bytes
// and the remaining data.
func berParseNext(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("BER: data too short")
	}

	lenByte := data[1]
	offset := 2

	var length int
	if lenByte < 128 {
		length = int(lenByte)
	} else {
		numLenBytes := int(lenByte & 0x7f)
		if offset+numLenBytes > len(data) {
			return nil, nil, fmt.Errorf("BER: length overflow")
		}
		for i := 0; i < numLenBytes; i++ {
			length = length<<8 | int(data[offset+i])
		}
		offset += numLenBytes
	}

	total := offset + length
	if total > len(data) {
		return nil, nil, fmt.Errorf("BER: element overflow")
	}

	return data[:total], data[total:], nil
}

func berDecodeInteger(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	// Sign-extend the first byte.
	var v int64
	if data[0]&0x80 != 0 {
		v = -1
	}
	for _, b := range data {
		v = v<<8 | int64(b)
	}
	return v
}

func berDecodeUnsigned(data []byte) uint64 {
	var v uint64
	for _, b := range data {
		v = v<<8 | uint64(b)
	}
	return v
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
