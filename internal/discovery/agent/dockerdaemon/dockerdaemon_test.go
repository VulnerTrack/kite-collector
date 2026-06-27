package dockerdaemon

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceDaemonJSON), "daemon-json"},
		{string(SourceNoConfig), "no-config"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`{"hosts":["unix:///var/run/docker.sock"]}`))
	b := HashContents([]byte(`{"hosts":["unix:///var/run/docker.sock"]}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsTCPHost(t *testing.T) {
	if !IsTCPHost("tcp://0.0.0.0:2375") {
		t.Fatal("tcp:// must flag")
	}
	if !IsTCPHost(" TCP://1.2.3.4:2376 ") {
		t.Fatal("case + whitespace tolerance")
	}
	for _, h := range []string{
		"unix:///var/run/docker.sock",
		"fd://",
		"npipe:////./pipe/docker_engine",
		"",
	} {
		if IsTCPHost(h) {
			t.Fatalf("%q must NOT flag", h)
		}
	}
}

func TestIsWorldBoundHost(t *testing.T) {
	world := []string{
		"tcp://0.0.0.0:2375",
		"tcp://:2375",
		"tcp://2375",
		"tcp://[::]:2375",
		"tcp://192.168.10.5:2376",
		"tcp://docker.corp.local:2376",
	}
	for _, h := range world {
		if !IsWorldBoundHost(h) {
			t.Fatalf("%q must flag world-bound", h)
		}
	}
	local := []string{
		"tcp://127.0.0.1:2375",
		"tcp://[::1]:2375",
		"tcp://localhost:2376",
		"unix:///var/run/docker.sock",
	}
	for _, h := range local {
		if IsWorldBoundHost(h) {
			t.Fatalf("%q must NOT flag world-bound", h)
		}
	}
}

func TestHasTCPSocket(t *testing.T) {
	if HasTCPSocket(nil) {
		t.Fatal("nil")
	}
	if HasTCPSocket([]string{"unix:///var/run/docker.sock"}) {
		t.Fatal("unix-only must NOT flag")
	}
	if !HasTCPSocket([]string{"unix:///var/run/docker.sock", "tcp://127.0.0.1:2376"}) {
		t.Fatal("mixed with tcp must flag")
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("got %q", got)
	}
}

// -- ParseDaemonJSON typical fixture ---------------------------------

func TestParseDaemonJSONTypicalHardened(t *testing.T) {
	body := []byte(`{
        "hosts": ["unix:///var/run/docker.sock"],
        "userns-remap": "default",
        "no-new-privileges": true,
        "iptables": true,
        "live-restore": true,
        "selinux-enabled": true,
        "log-driver": "journald",
        "storage-driver": "overlay2",
        "default-runtime": "runc"
    }`)
	got, err := ParseDaemonJSON(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	AnnotateSecurity(&got)
	if got.IsTCPSocketExposed || got.IsTCPSocketWorldExposed {
		t.Fatal("unix-only daemon must not flag TCP exposure")
	}
	if got.HasInsecureRegistries {
		t.Fatal("no insecure-registries → must NOT flag")
	}
	if !got.IsUsernsRemapped || !got.IsNoNewPrivilegesDefault ||
		!got.IsIptablesManaged || !got.IsLiveRestoreEnabled ||
		!got.IsSELinuxEnabled {
		t.Fatalf("hardened flags missing: %+v", got)
	}
	if !got.IsHardened {
		t.Fatalf("rolled-up IsHardened must be true: %+v", got)
	}
}

// -- ParseDaemonJSON worst-case ---------------------------------------

func TestParseDaemonJSONWorstCase(t *testing.T) {
	body := []byte(`{
        "hosts": ["tcp://0.0.0.0:2375"],
        "insecure-registries": ["registry.internal:5000"],
        "userns-remap": "",
        "no-new-privileges": false,
        "iptables": false,
        "experimental": true
    }`)
	got, err := ParseDaemonJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	AnnotateSecurity(&got)
	if !got.IsTCPSocketExposed || !got.IsTCPSocketWorldExposed {
		t.Fatal("tcp://0.0.0.0 must flag world-exposed")
	}
	if got.IsTLSEnabled || got.IsTLSVerifyEnabled {
		t.Fatal("no TLS keys → must NOT flag TLS")
	}
	if !got.HasInsecureRegistries {
		t.Fatal("insecure-registries set → must flag")
	}
	if got.IsUsernsRemapped {
		t.Fatal("empty userns-remap = NOT remapped")
	}
	if got.IsNoNewPrivilegesDefault {
		t.Fatal("no-new-privileges=false must propagate")
	}
	if got.IsIptablesManaged {
		t.Fatal("iptables=false must propagate")
	}
	if !got.IsExperimentalEnabled {
		t.Fatal("experimental=true must propagate")
	}
	if got.IsHardened {
		t.Fatalf("rolled-up IsHardened must be false: %+v", got)
	}
}

// -- ParseDaemonJSON default fill --------------------------------------

func TestParseDaemonJSONEmptyObjectGetsDefaults(t *testing.T) {
	// `{}` = pure-default daemon. iptables defaults true; everything
	// else defaults false. The pipeline still gets a row.
	got, err := ParseDaemonJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsIptablesManaged {
		t.Fatal("default iptables=true must propagate")
	}
	if got.IsNoNewPrivilegesDefault || got.IsLiveRestoreEnabled ||
		got.IsSELinuxEnabled {
		t.Fatalf("missing keys must keep their false defaults: %+v", got)
	}
}

// -- TLS detection: TLS flag OR cert path -----------------------------

func TestParseDaemonJSONTLSDetectionViaCertPaths(t *testing.T) {
	body := []byte(`{
        "hosts": ["tcp://10.0.0.5:2376"],
        "tlsverify": true,
        "tlscacert": "/etc/docker/ca.pem",
        "tlscert":   "/etc/docker/server.pem",
        "tlskey":    "/etc/docker/server.key"
    }`)
	got, err := ParseDaemonJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	AnnotateSecurity(&got)
	if !got.IsTLSEnabled || !got.IsTLSVerifyEnabled {
		t.Fatalf("TLS enabled + verify must flag: %+v", got)
	}
	if !got.IsTCPSocketWorldExposed {
		t.Fatal("non-loopback IP must flag world-exposed")
	}
}

// -- dedupeNonEmpty -------------------------------------------------

func TestParseDaemonJSONDedupesHosts(t *testing.T) {
	body := []byte(`{"hosts":["unix:///var/run/docker.sock","unix:///var/run/docker.sock","","tcp://127.0.0.1:2376"]}`)
	got, err := ParseDaemonJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 {
		t.Fatalf("dedupe broken: %+v", got.Hosts)
	}
}

// -- BOM tolerance --------------------------------------------------

func TestParseDaemonJSONStripsBOM(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"hosts":["unix:///x"]}`)...)
	got, err := ParseDaemonJSON(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if len(got.Hosts) != 1 {
		t.Fatalf("hosts=%+v", got.Hosts)
	}
}

// -- error paths ----------------------------------------------------

func TestParseDaemonJSONEmpty(t *testing.T) {
	if _, err := ParseDaemonJSON(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseDaemonJSONMalformed(t *testing.T) {
	if _, err := ParseDaemonJSON([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- IsHardened -----------------------------------------------------

func TestIsHardenedRequiresAllKnobs(t *testing.T) {
	base := State{
		IsNoNewPrivilegesDefault: true,
		UsernsRemap:              "default",
		IsIptablesManaged:        true,
	}
	AnnotateSecurity(&base)
	if !base.IsHardened {
		t.Fatalf("baseline must be hardened: %+v", base)
	}

	// Flip any single knob → un-harden.
	cases := []State{
		{IsNoNewPrivilegesDefault: false, UsernsRemap: "default", IsIptablesManaged: true},
		{IsNoNewPrivilegesDefault: true, UsernsRemap: "", IsIptablesManaged: true},
		{IsNoNewPrivilegesDefault: true, UsernsRemap: "default", IsIptablesManaged: false},
	}
	for i, c := range cases {
		AnnotateSecurity(&c)
		if c.IsHardened {
			t.Fatalf("case %d must NOT be hardened: %+v", i, c)
		}
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorParsesAndAnnotates(t *testing.T) {
	body := []byte(`{
        "hosts": ["tcp://0.0.0.0:2375"],
        "insecure-registries": ["10.0.0.5:5000"]
    }`)
	c := &fileCollector{
		configPath: "/fake/etc/docker/daemon.json",
		readFile: func(p string) ([]byte, error) {
			if p != "/fake/etc/docker/daemon.json" {
				t.Fatalf("unexpected path: %s", p)
			}
			return body, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.Source != SourceDaemonJSON {
		t.Fatalf("source=%q", got.Source)
	}
	if got.ConfigPath != "/fake/etc/docker/daemon.json" {
		t.Fatalf("config_path=%q", got.ConfigPath)
	}
	if got.FileHash == "" {
		t.Fatal("file_hash missing")
	}
	if !got.IsTCPSocketWorldExposed || !got.HasInsecureRegistries {
		t.Fatalf("flags wrong: %+v", got)
	}
	if got.IsHardened {
		t.Fatal("worst-case must NOT be hardened")
	}
}

func TestFileCollectorMissingFileReturnsNoConfig(t *testing.T) {
	c := &fileCollector{
		configPath: "/nope/daemon.json",
		readFile: func(string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if got.Source != SourceNoConfig {
		t.Fatalf("source=%q want no-config", got.Source)
	}
}

func TestFileCollectorReadErrorPropagates(t *testing.T) {
	boom := errors.New("io boom")
	c := &fileCollector{
		configPath: "/x",
		readFile: func(string) ([]byte, error) {
			return nil, boom
		},
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("read error must propagate")
	}
	if got.Source != SourceUnknown {
		t.Fatalf("source=%q want unknown", got.Source)
	}
}

func TestFileCollectorMalformedFile(t *testing.T) {
	c := &fileCollector{
		configPath: "/x",
		readFile: func(string) ([]byte, error) {
			return []byte("not json"), nil
		},
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("malformed must error")
	}
	if got.Source != SourceUnknown {
		t.Fatalf("source=%q want unknown", got.Source)
	}
	if got.ConfigPath != "/x" {
		t.Fatalf("path missing: %q", got.ConfigPath)
	}
}

// -- SortLists ------------------------------------------------------

func TestSortListsDeterministic(t *testing.T) {
	s := State{
		Hosts:              []string{"unix:///z", "tcp://1.2.3.4:5", "unix:///a"},
		InsecureRegistries: []string{"z.local", "a.local"},
		RegistryMirrors:    []string{"m2", "m1"},
	}
	SortLists(&s)
	if !strings.HasSuffix(s.Hosts[0], "1.2.3.4:5") {
		t.Fatalf("Hosts not sorted: %+v", s.Hosts)
	}
	if s.InsecureRegistries[0] != "a.local" {
		t.Fatalf("InsecureRegistries not sorted: %+v", s.InsecureRegistries)
	}
	if s.RegistryMirrors[0] != "m1" {
		t.Fatalf("RegistryMirrors not sorted: %+v", s.RegistryMirrors)
	}
}
