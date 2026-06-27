package wsdiscovery

import (
	"net"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestBuildProbeIsWellFormedSOAP(t *testing.T) {
	pkt := string(buildProbe("uuid:test-mid", ""))
	wants := []string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`xmlns:s="http://www.w3.org/2003/05/soap-envelope"`,
		`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"`,
		`<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>`,
		`<a:MessageID>uuid:test-mid</a:MessageID>`,
		`<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>`,
		`<d:Probe>`,
	}
	for _, w := range wants {
		if !strings.Contains(pkt, w) {
			t.Fatalf("Probe missing %q\n---\n%s", w, pkt)
		}
	}
	if strings.Contains(pkt, "<d:Types>") {
		t.Fatalf("empty types must not emit Types element")
	}
}

func TestBuildProbeWithTypeFilter(t *testing.T) {
	pkt := string(buildProbe("uuid:x", "dn:NetworkVideoTransmitter"))
	if !strings.Contains(pkt, `<d:Types>dn:NetworkVideoTransmitter</d:Types>`) {
		t.Fatalf("type filter missing: %s", pkt)
	}
}

func TestBuildProbeEscapesMessageID(t *testing.T) {
	pkt := string(buildProbe(`uuid:has"&<chars`, ""))
	if !strings.Contains(pkt, `uuid:has&quot;&amp;&lt;chars`) {
		t.Fatalf("escaping failed: %s", pkt)
	}
}

func TestParseEnvelope_ProbeMatchONVIF(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
  </s:Header>
  <s:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <a:EndpointReference>
          <a:Address>urn:uuid:0a000000-0000-0000-0000-0123456789ab</a:Address>
        </a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/IPCAM-X</d:Scopes>
        <d:XAddrs>http://192.168.1.64/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>`)
	pms, err := parseEnvelope(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pms) != 1 {
		t.Fatalf("want 1 match, got %d", len(pms))
	}
	pm := pms[0]
	if pm.Address != "urn:uuid:0a000000-0000-0000-0000-0123456789ab" {
		t.Fatalf("address lost: %q", pm.Address)
	}
	if pm.Types != "dn:NetworkVideoTransmitter" {
		t.Fatalf("types lost: %q", pm.Types)
	}
	if !strings.Contains(pm.Scopes, "onvif://www.onvif.org/Profile/Streaming") {
		t.Fatalf("scopes lost: %q", pm.Scopes)
	}
	if len(pm.XAddrs) != 2 {
		t.Fatalf("xaddrs not split: %v", pm.XAddrs)
	}
}

func TestParseEnvelope_HelloIsAlsoExtracted(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <Hello xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <EndpointReference xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <Address>urn:uuid:abc</Address>
      </EndpointReference>
      <Types>pub:Computer</Types>
      <Scopes>microsoft.com/windows/domain</Scopes>
      <XAddrs>http://10.0.0.5:5357/wsd</XAddrs>
    </Hello>
  </Body>
</Envelope>`)
	pms, err := parseEnvelope(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pms) != 1 {
		t.Fatalf("want 1 hello match, got %d", len(pms))
	}
	if pms[0].Address != "urn:uuid:abc" {
		t.Fatalf("hello address lost: %q", pms[0].Address)
	}
	if !strings.Contains(pms[0].Types, "Computer") {
		t.Fatalf("hello types lost: %q", pms[0].Types)
	}
}

func TestAbsorbAndClassifyCamera(t *testing.T) {
	r := &responder{}
	absorb(r, probeMatch{
		Address: "urn:uuid:cam",
		Types:   "dn:NetworkVideoTransmitter",
		Scopes:  "onvif://www.onvif.org/Profile/Streaming",
		XAddrs:  []string{"http://192.168.1.64/onvif/device_service"},
	})
	if r.hostname != "192.168.1.64" {
		t.Fatalf("hostname from xaddr missing: %q", r.hostname)
	}
	if got := classify(r.types, r.scopes); got != model.AssetTypeIOTDevice {
		t.Fatalf("camera must be iot_device, got %v", got)
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		types  string
		scopes string
		want   model.AssetType
	}{
		{"onvif camera", "dn:NetworkVideoTransmitter", "onvif://www.onvif.org/Profile/Streaming", model.AssetTypeIOTDevice},
		{"printer by type", "wprt:PrinterServiceV10", "ldap.printer.example/", model.AssetTypeAppliance},
		{"windows computer", "pub:Computer", "microsoft.com/windows/domain", model.AssetTypeWorkstation},
		{"generic device", "wsdp:Device", "", model.AssetTypeIOTDevice},
		{"unknown", "", "", model.AssetTypeIOTDevice},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.types, tc.scopes); got != tc.want {
				t.Fatalf("classify(%q,%q) = %v, want %v", tc.types, tc.scopes, got, tc.want)
			}
		})
	}
}

func TestAssetsFromRespondersDeterministicAndKeyed(t *testing.T) {
	rs := map[string]*responder{
		"urn:uuid:cam": {
			addr:     net.ParseIP("192.168.1.64"),
			epr:      "urn:uuid:cam",
			types:    "dn:NetworkVideoTransmitter",
			scopes:   "onvif://www.onvif.org/Profile/Streaming",
			xaddrs:   []string{"http://192.168.1.64/onvif/device_service"},
			hostname: "192.168.1.64",
		},
		"urn:uuid:pc": {
			addr:   net.ParseIP("192.168.1.10"),
			epr:    "urn:uuid:pc",
			types:  "pub:Computer",
			scopes: "microsoft.com/windows/domain",
			xaddrs: []string{"http://192.168.1.10:5357/wsd"},
		},
	}
	got := assetsFromResponders(rs)
	if len(got) != 2 {
		t.Fatalf("want 2 assets, got %d", len(got))
	}
	// Sorted by key — "urn:uuid:cam" < "urn:uuid:pc".
	if got[0].Hostname != "192.168.1.64" {
		t.Fatalf("first asset hostname=%q", got[0].Hostname)
	}
	if got[0].AssetType != model.AssetTypeIOTDevice {
		t.Fatalf("camera not iot_device: %v", got[0].AssetType)
	}
	if got[1].AssetType != model.AssetTypeWorkstation {
		t.Fatalf("pc not workstation: %v", got[1].AssetType)
	}
	if !strings.Contains(got[0].Tags, "onvif://www.onvif.org/Profile/Streaming") {
		t.Fatalf("scopes missing from tags: %s", got[0].Tags)
	}
	if got[0].DiscoverySource != "wsdiscovery" {
		t.Fatalf("source not stamped: %q", got[0].DiscoverySource)
	}
	if got[0].NaturalKey == "" {
		t.Fatalf("natural key not computed")
	}
}

func TestMergeSpaceListDedupes(t *testing.T) {
	out := mergeSpaceList("dn:NetworkVideoTransmitter foo", "foo bar")
	if out != "dn:NetworkVideoTransmitter foo bar" {
		t.Fatalf("merge result: %q", out)
	}
}

func TestParseConfigClampsWindow(t *testing.T) {
	c := parseConfig(map[string]any{"listen_window": "999s"})
	if c.ListenWindow != maxListenWin {
		t.Fatalf("listen_window not clamped: %v", c.ListenWindow)
	}
}
