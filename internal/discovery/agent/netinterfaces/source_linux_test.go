//go:build linux

package netinterfaces

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeIface(t *testing.T, root, name string, kv map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceEnumeratesNet(t *testing.T) {
	root := t.TempDir()

	writeIface(t, root, "eth0", map[string]string{
		"address":      "aa:bb:cc:dd:ee:ff\n",
		"operstate":    "up\n",
		"carrier":      "1\n",
		"mtu":          "1500\n",
		"speed":        "1000\n",
		"duplex":       "full\n",
		"tx_queue_len": "1000\n",
		"flags":        "0x1003\n", // IFF_UP + IFF_BROADCAST + IFF_MULTICAST
	})
	writeIface(t, root, "wlan0", map[string]string{
		"address":   "11:22:33:44:55:66",
		"operstate": "up",
		"carrier":   "1",
		"flags":     "0x1103", // IFF_UP + IFF_BROADCAST + IFF_PROMISC + IFF_MULTICAST
	})
	writeIface(t, root, "lo", map[string]string{
		"address":   "00:00:00:00:00:00",
		"operstate": "unknown",
		"carrier":   "1",
	})

	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	by := map[string]Iface{}
	for _, i := range got {
		by[i.Iface] = i
	}
	if by["eth0"].SpeedMbps != 1000 || by["eth0"].Duplex != DuplexFull {
		t.Fatalf("eth0 link: %+v", by["eth0"])
	}
	if by["eth0"].Operstate != OpUp || !by["eth0"].Carrier {
		t.Fatalf("eth0 state wrong: %+v", by["eth0"])
	}
	if by["eth0"].rawMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("eth0 raw MAC=%q", by["eth0"].rawMAC)
	}
	if !by["wlan0"].IsPromiscuous {
		t.Fatalf("wlan0 promisc not detected: %+v", by["wlan0"])
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	got, err := NewLinuxSource(filepath.Join(t.TempDir(), "nope")).
		Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestCollectorEndToEndAnnotations(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, "eth0", map[string]string{
		"address":   "aa:bb:cc:dd:ee:ff",
		"operstate": "up",
		"carrier":   "0",   // physical with no carrier → risk
		"speed":     "100", // < 1 Gb → low-speed risk
	})
	got, err := NewCollectorWith(NewLinuxSource(root)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[0].IsNoCarrierRisk {
		t.Fatalf("no-carrier risk missing: %+v", got[0])
	}
	if !got[0].IsLowSpeedRisk {
		t.Fatalf("low-speed risk missing: %+v", got[0])
	}
	if got[0].MACAddressHash == "" || got[0].OUIHex != "aabbcc" {
		t.Fatalf("MAC handling drift: %+v", got[0])
	}
}
