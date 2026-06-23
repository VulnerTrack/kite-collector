package ssdp

import (
	"net"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestBuildMSearchHasMandatoryHeaders(t *testing.T) {
	pkt := buildMSearch(ssdpIPv4, "ssdp:all", 2)
	s := string(pkt)
	wants := []string{
		"M-SEARCH * HTTP/1.1\r\n",
		"HOST: 239.255.255.250:1900\r\n",
		"MAN: \"ssdp:discover\"\r\n",
		"MX: 2\r\n",
		"ST: ssdp:all\r\n",
	}
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Fatalf("M-SEARCH missing %q\n---\n%s", w, s)
		}
	}
	if !strings.HasSuffix(s, "\r\n\r\n") {
		t.Fatalf("M-SEARCH must end with blank line; got %q", s[len(s)-6:])
	}
}

func TestBuildMSearchIPv6BracketsHost(t *testing.T) {
	pkt := buildMSearch(ssdpIPv6, "ssdp:all", 2)
	if !strings.Contains(string(pkt), "HOST: [ff02::c]:1900\r\n") {
		t.Fatalf("expected bracketed v6 HOST header, got:\n%s", pkt)
	}
}

func TestParseDatagram_Response(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://192.168.1.1:49152/rootDesc.xml\r\n" +
		"SERVER: Linux/4.14 UPnP/2.0 MiniDLNA/1.3.0\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"USN: uuid:11111111-2222-3333-4444-555555555555::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"\r\n")
	msg, err := parseDatagram(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Method != "" {
		t.Fatalf("response must not have a method, got %q", msg.Method)
	}
	if got := msg.Headers.Get("Location"); got != "http://192.168.1.1:49152/rootDesc.xml" {
		t.Fatalf("Location header lost: %q", got)
	}
	if got := msg.Headers.Get("St"); !strings.Contains(got, "InternetGatewayDevice") {
		t.Fatalf("ST header lost: %q", got)
	}
}

func TestParseDatagram_NotifyAlive(t *testing.T) {
	raw := []byte("NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"NT: urn:dial-multiscreen-org:device:dial:1\r\n" +
		"NTS: ssdp:alive\r\n" +
		"USN: uuid:abc::urn:dial-multiscreen-org:device:dial:1\r\n" +
		"\r\n")
	msg, err := parseDatagram(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Method != "NOTIFY" {
		t.Fatalf("expected NOTIFY method, got %q", msg.Method)
	}
	if msg.NTS != "ssdp:alive" {
		t.Fatalf("expected NTS=ssdp:alive, got %q", msg.NTS)
	}
	if msg.Headers.Get("Nt") == "" {
		t.Fatalf("NT header lost")
	}
}

func TestParseDatagram_RejectsForeignMSearch(t *testing.T) {
	raw := []byte("M-SEARCH * HTTP/1.1\r\nHOST: x\r\n\r\n")
	if _, err := parseDatagram(raw); err == nil {
		t.Fatalf("expected error for foreign M-SEARCH")
	}
}

func TestAbsorbAndClassifyGateway(t *testing.T) {
	r := &responder{sts: map[string]struct{}{}, usns: map[string]struct{}{}}
	msg := ssdpMessage{Headers: make(map[string][]string)}
	msg.Headers.Set("Server", "Linux/4.14 UPnP/2.0 MiniDLNA/1.3.0")
	msg.Headers.Set("Location", "http://192.168.1.1:49152/rootDesc.xml")
	msg.Headers.Set("St", "urn:schemas-upnp-org:device:InternetGatewayDevice:1")
	msg.Headers.Set("Usn", "uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1")
	absorbMessage(r, msg)
	if r.hostname != "192.168.1.1" {
		t.Fatalf("hostname lost: %q", r.hostname)
	}
	if r.location == "" || r.server == "" || r.usn == "" {
		t.Fatalf("absorb dropped fields: %+v", r)
	}
	if got := classify(r.sts, r.server); got != model.AssetTypeNetworkDevice {
		t.Fatalf("gateway must classify as network_device, got %v", got)
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		sts    []string
		server string
		want   model.AssetType
	}{
		{
			"gateway wins over mediarenderer",
			[]string{
				"urn:schemas-upnp-org:device:MediaRenderer:1",
				"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			},
			"",
			model.AssetTypeNetworkDevice,
		},
		{
			"printer from server header",
			[]string{"upnp:rootdevice"},
			"Printer-Daemon IPP/2.0",
			model.AssetTypeAppliance,
		},
		{
			"mediarenderer",
			[]string{"urn:schemas-upnp-org:device:MediaRenderer:1"},
			"",
			model.AssetTypeIOTDevice,
		},
		{
			"unknown falls back to iot",
			[]string{"upnp:rootdevice"},
			"",
			model.AssetTypeIOTDevice,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]struct{}{}
			for _, s := range tc.sts {
				m[s] = struct{}{}
			}
			if got := classify(m, tc.server); got != tc.want {
				t.Fatalf("classify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssetsFromRespondersIsDeterministic(t *testing.T) {
	r1 := &responder{
		addr:     net.IPv4(192, 168, 1, 1),
		hostname: "192.168.1.1",
		server:   "Linux UPnP/2.0",
		sts:      map[string]struct{}{"urn:schemas-upnp-org:device:InternetGatewayDevice:1": {}},
		usns:     map[string]struct{}{"uuid:aaa::urn:schemas-upnp-org:device:InternetGatewayDevice:1": {}},
	}
	r2 := &responder{
		addr:     net.IPv4(192, 168, 1, 50),
		hostname: "tv.local",
		server:   "Samsung UPnP/1.0",
		sts:      map[string]struct{}{"urn:schemas-upnp-org:device:MediaRenderer:1": {}},
		usns:     map[string]struct{}{"uuid:bbb::urn:schemas-upnp-org:device:MediaRenderer:1": {}},
	}
	got := assetsFromResponders(map[string]*responder{
		"192.168.1.50": r2,
		"192.168.1.1":  r1,
	})
	if len(got) != 2 {
		t.Fatalf("want 2 assets, got %d", len(got))
	}
	if got[0].Hostname != "192.168.1.1" || got[1].Hostname != "tv.local" {
		t.Fatalf("sort order wrong: %q, %q", got[0].Hostname, got[1].Hostname)
	}
	if got[0].AssetType != model.AssetTypeNetworkDevice {
		t.Fatalf("router not classified as network_device: %v", got[0].AssetType)
	}
	if got[1].AssetType != model.AssetTypeIOTDevice {
		t.Fatalf("tv not classified as iot_device: %v", got[1].AssetType)
	}
	if !strings.Contains(got[0].Tags, "InternetGatewayDevice") {
		t.Fatalf("tags missing ST: %s", got[0].Tags)
	}
	if !strings.Contains(got[0].Tags, `"ssdp_server":"Linux UPnP/2.0"`) {
		t.Fatalf("server header missing from tags: %s", got[0].Tags)
	}
}

func TestParseConfigClampsMXAndWindow(t *testing.T) {
	c := parseConfig(map[string]any{
		"listen_window": "9999s",
		"mx":            42,
	})
	if c.ListenWindow != maxListenWin {
		t.Fatalf("listen_window not clamped: %v", c.ListenWindow)
	}
	if c.MX != 5 {
		t.Fatalf("MX not clamped to 5: %d", c.MX)
	}
	c = parseConfig(map[string]any{"mx": 0})
	if c.MX != 1 {
		t.Fatalf("MX floor not applied: %d", c.MX)
	}
}
