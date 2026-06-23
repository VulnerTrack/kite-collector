package lldp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const sampleLLDPCtl = `{
  "lldp": {
    "interface": [
      {
        "eth0": {
          "via": "LLDP",
          "rid": "1",
          "age": "0 day, 00:00:42",
          "chassis": {
            "switch-01.lab.example": {
              "id": {"type": "mac", "value": "aa:bb:cc:dd:ee:ff"},
              "descr": "Cisco IOS Software, IOS-XE",
              "mgmt-ip": ["10.0.0.1", "fe80::1"],
              "capability": [
                {"type": "Bridge", "enabled": true},
                {"type": "Router", "enabled": true},
                {"type": "Telephone", "enabled": false}
              ]
            }
          },
          "port": {
            "id": {"type": "ifname", "value": "GigabitEthernet0/1"},
            "descr": "Uplink to core",
            "ttl": "120"
          },
          "vlan": [
            {"vlan-id": "10", "value": "users"},
            {"vlan-id": "20", "value": "voice"}
          ]
        }
      },
      {
        "eth1": {
          "chassis": {
            "switch-01.lab.example": {
              "id": {"type": "mac", "value": "aa:bb:cc:dd:ee:ff"},
              "descr": "Cisco IOS Software, IOS-XE",
              "mgmt-ip": ["10.0.0.1"],
              "capability": [
                {"type": "Bridge", "enabled": true},
                {"type": "Router", "enabled": true}
              ]
            }
          },
          "port": {
            "id": {"type": "ifname", "value": "GigabitEthernet0/2"},
            "descr": "Uplink to core (redundant)"
          }
        }
      }
    ]
  }
}`

func TestParseLLDPCtlExtractsAllFields(t *testing.T) {
	ns, err := parseLLDPCtl([]byte(sampleLLDPCtl))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ns) != 2 {
		t.Fatalf("want 2 neighbors, got %d", len(ns))
	}
	first := ns[0]
	if first.LocalIface != "eth0" {
		t.Fatalf("local iface lost: %q", first.LocalIface)
	}
	if first.ChassisName != "switch-01.lab.example" {
		t.Fatalf("chassis name lost: %q", first.ChassisName)
	}
	if first.ChassisID != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("chassis id lost: %q", first.ChassisID)
	}
	if first.PortID != "GigabitEthernet0/1" {
		t.Fatalf("port id lost: %q", first.PortID)
	}
	if first.PortDescr != "Uplink to core" {
		t.Fatalf("port descr lost: %q", first.PortDescr)
	}
	if first.MgmtIP != "10.0.0.1" {
		t.Fatalf("mgmt ip lost: %q", first.MgmtIP)
	}
	if len(first.Capabilities) != 2 ||
		first.Capabilities[0] != "Bridge" || first.Capabilities[1] != "Router" {
		t.Fatalf("capabilities lost (only Enabled=true should pass): %v", first.Capabilities)
	}
	if len(first.VLANs) != 2 {
		t.Fatalf("vlans lost: %v", first.VLANs)
	}
}

func TestAssetsFromNeighborsCollapsesByChassis(t *testing.T) {
	ns, err := parseLLDPCtl([]byte(sampleLLDPCtl))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assets := assetsFromNeighbors(ns)
	if len(assets) != 1 {
		t.Fatalf("two uplinks to same chassis must collapse: got %d assets", len(assets))
	}
	a := assets[0]
	if a.Hostname != "switch-01.lab.example" {
		t.Fatalf("hostname not chassis name: %q", a.Hostname)
	}
	if a.AssetType != model.AssetTypeNetworkDevice {
		t.Fatalf("Bridge+Router must classify as network_device, got %v", a.AssetType)
	}
	if a.DiscoverySource != "lldp" {
		t.Fatalf("source not stamped: %q", a.DiscoverySource)
	}
	if !strings.Contains(a.Tags, `"local_iface":"eth0"`) {
		t.Fatalf("eth0 edge missing: %s", a.Tags)
	}
	if !strings.Contains(a.Tags, `"local_iface":"eth1"`) {
		t.Fatalf("eth1 edge missing: %s", a.Tags)
	}
	if !strings.Contains(a.Tags, `"port_id":"GigabitEthernet0/1"`) {
		t.Fatalf("port id missing: %s", a.Tags)
	}
	if !strings.Contains(a.Tags, `"lldp_vlans":["10","20"]`) {
		t.Fatalf("vlans missing or unsorted: %s", a.Tags)
	}
	if a.NaturalKey == "" {
		t.Fatalf("natural key not computed")
	}
}

func TestParseLLDPCtlEmpty(t *testing.T) {
	ns, err := parseLLDPCtl([]byte(`{"lldp":{}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ns) != 0 {
		t.Fatalf("want 0 neighbors, got %d", len(ns))
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		caps  []string
		descr string
		want  model.AssetType
	}{
		{"bridge is network device", []string{"Bridge"}, "", model.AssetTypeNetworkDevice},
		{"router is network device", []string{"Router"}, "", model.AssetTypeNetworkDevice},
		{"wlan ap is network device", []string{"WLAN-Access-Point"}, "", model.AssetTypeNetworkDevice},
		{"station-only is server", []string{"Station-Only"}, "Ubuntu 24.04", model.AssetTypeServer},
		{"linux descr → server", nil, "Linux 6.5", model.AssetTypeServer},
		{"unknown → network_device default", nil, "", model.AssetTypeNetworkDevice},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.caps, tc.descr); got != tc.want {
				t.Fatalf("classify(%v,%q) = %v, want %v", tc.caps, tc.descr, got, tc.want)
			}
		})
	}
}

func TestDiscoverSkipsWhenLLDPCtlMissing(t *testing.T) {
	s := &Source{
		run: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			t.Fatalf("run must not be invoked when binary is missing")
			return nil, nil
		},
		lookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	}
	out, err := s.Discover(context.Background(), nil)
	if err != nil {
		t.Fatalf("missing daemon must not error, got: %v", err)
	}
	if out != nil {
		t.Fatalf("want nil assets, got %d", len(out))
	}
}

func TestDiscoverEndToEndWithFakeRunner(t *testing.T) {
	s := &Source{
		run: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			if binary != "/usr/sbin/lldpctl" {
				t.Fatalf("binary path passed through wrong: %q", binary)
			}
			if len(args) != 2 || args[0] != "-f" || args[1] != "json" {
				t.Fatalf("expected -f json, got %v", args)
			}
			return []byte(sampleLLDPCtl), nil
		},
		lookPath: func(name string) (string, error) {
			if name != "lldpctl" {
				t.Fatalf("expected lookup of 'lldpctl', got %q", name)
			}
			return "/usr/sbin/lldpctl", nil
		},
	}
	out, err := s.Discover(context.Background(), nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 asset, got %d", len(out))
	}
	if out[0].Hostname != "switch-01.lab.example" {
		t.Fatalf("asset hostname: %q", out[0].Hostname)
	}
}

func TestParseConfigOverridesBinaryAndTimeout(t *testing.T) {
	c := parseConfig(map[string]any{
		"binary":  "/opt/lldpd/bin/lldpctl",
		"timeout": "12s",
	})
	if c.Binary != "/opt/lldpd/bin/lldpctl" {
		t.Fatalf("binary override lost: %q", c.Binary)
	}
	if c.Timeout.String() != "12s" {
		t.Fatalf("timeout override lost: %v", c.Timeout)
	}
}
