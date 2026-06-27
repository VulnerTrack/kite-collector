package listeners

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyExposure(t *testing.T) {
	cases := map[string]Exposure{
		"0.0.0.0":         ExposureInternet,
		"::":              ExposureInternet,
		"":                ExposureInternet,
		"*":               ExposureInternet,
		"127.0.0.1":       ExposureLoopback,
		"127.5.6.7":       ExposureLoopback,
		"::1":             ExposureLoopback,
		"10.0.0.5":        ExposureLAN,
		"172.16.1.2":      ExposureLAN,
		"192.168.1.100":   ExposureLAN,
		"169.254.169.254": ExposureLAN, // link-local
		"fe80::1":         ExposureLAN,
		"8.8.8.8":         ExposureInternet,
		"2001:db8::1":     ExposureInternet,
		"not-an-ip":       ExposureUnknown,
	}
	for in, want := range cases {
		if got := ClassifyExposure(in); got != want {
			t.Fatalf("ClassifyExposure(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortListenersDeterministic(t *testing.T) {
	in := []Listener{
		{Protocol: ProtoUDP, BindAddress: "0.0.0.0", Port: 53},
		{Protocol: ProtoTCP, BindAddress: "0.0.0.0", Port: 22},
		{Protocol: ProtoTCP, BindAddress: "127.0.0.1", Port: 631},
		{Protocol: ProtoTCP, BindAddress: "0.0.0.0", Port: 80},
		{Protocol: ProtoTCP6, BindAddress: "::", Port: 22},
	}
	SortListeners(in)
	want := []struct {
		proto Protocol
		addr  string
		port  uint16
	}{
		{ProtoTCP, "0.0.0.0", 22},
		{ProtoTCP, "0.0.0.0", 80},
		{ProtoTCP, "127.0.0.1", 631},
		{ProtoTCP6, "::", 22},
		{ProtoUDP, "0.0.0.0", 53},
	}
	for i, l := range in {
		w := want[i]
		if l.Protocol != w.proto || l.BindAddress != w.addr || l.Port != w.port {
			t.Fatalf("pos %d: got (%q,%q,%d), want (%q,%q,%d)",
				i, l.Protocol, l.BindAddress, l.Port,
				w.proto, w.addr, w.port)
		}
	}
}

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ProtoTCP), "tcp"},
		{string(ProtoTCP6), "tcp6"},
		{string(ProtoUDP), "udp"},
		{string(ProtoUDP6), "udp6"},
		{string(ExposureInternet), "internet"},
		{string(ExposureLAN), "lan"},
		{string(ExposureLoopback), "loopback"},
		{string(ExposureUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestClassifyProto(t *testing.T) {
	const (
		AFInet     uint32 = 2
		AFInet6    uint32 = 10
		SOCKStream uint32 = 1
		SOCKDgram  uint32 = 2
	)
	cases := []struct {
		want     Protocol
		family   uint32
		sockType uint32
	}{
		{ProtoTCP, AFInet, SOCKStream},
		{ProtoTCP6, AFInet6, SOCKStream},
		{ProtoUDP, AFInet, SOCKDgram},
		{ProtoUDP6, AFInet6, SOCKDgram},
	}
	for _, tc := range cases {
		if got := classifyProto(tc.family, tc.sockType); got != tc.want {
			t.Fatalf("classifyProto(%d,%d) = %q, want %q",
				tc.family, tc.sockType, got, tc.want)
		}
	}
}

func TestIsListening(t *testing.T) {
	cases := []struct {
		conn Conn
		want bool
	}{
		// TCP LISTEN — yes
		{Conn{Type: 1, Status: "LISTEN", LocalPort: 22}, true},
		// TCP ESTABLISHED — no, this is a client/server connected socket
		{Conn{Type: 1, Status: "ESTABLISHED", LocalPort: 22}, false},
		// UDP bound — yes, no formal LISTEN state but exposed
		{Conn{Type: 2, Status: "", LocalPort: 53}, true},
		// Port 0 — kernel hasn't assigned, ignore
		{Conn{Type: 1, Status: "LISTEN", LocalPort: 0}, false},
		// Status case-insensitive
		{Conn{Type: 1, Status: "listen", LocalPort: 22}, true},
	}
	for _, tc := range cases {
		if got := isListening(tc.conn); got != tc.want {
			t.Fatalf("isListening(%+v) = %v, want %v", tc.conn, got, tc.want)
		}
	}
}

func TestCollectFiltersListenStateAndStampsProcess(t *testing.T) {
	src := &fakeSource{
		conns: map[string][]Conn{
			"tcp": {
				{Family: 2, Type: 1, Status: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 22, PID: 100},
				{Family: 2, Type: 1, Status: "LISTEN", LocalIP: "127.0.0.1", LocalPort: 631, PID: 200},
				{Family: 2, Type: 1, Status: "ESTABLISHED", LocalIP: "10.0.0.1", LocalPort: 54321, PID: 999},
				{Family: 10, Type: 1, Status: "LISTEN", LocalIP: "::", LocalPort: 22, PID: 100},
			},
			"udp": {
				{Family: 2, Type: 2, Status: "", LocalIP: "0.0.0.0", LocalPort: 53, PID: 300},
				{Family: 10, Type: 2, Status: "", LocalIP: "::1", LocalPort: 5353, PID: 400},
			},
		},
		processes: map[int32]struct{ name, exe, user string }{
			100: {"sshd", "/usr/sbin/sshd", "root"},
			200: {"cupsd", "/usr/sbin/cupsd", "root"},
			300: {"dnsmasq", "/usr/sbin/dnsmasq", "dnsmasq"},
			400: {"avahi-daemon", "/usr/sbin/avahi-daemon", "avahi"},
		},
	}
	c := &gopsutilCollector{src: src}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 4 listeners after filtering out the ESTABLISHED conn.
	if len(got) != 5 {
		t.Fatalf("want 5 listeners, got %d: %+v", len(got), got)
	}

	by := map[string]Listener{}
	for _, l := range got {
		by[string(l.Protocol)+":"+l.BindAddress+":"+itoa(int(l.Port))] = l
	}

	// ssh on 0.0.0.0 → internet exposure, process linked.
	ssh := by["tcp:0.0.0.0:22"]
	if ssh.Exposure != ExposureInternet {
		t.Fatalf("ssh exposure=%q, want internet", ssh.Exposure)
	}
	if ssh.ProcessName != "sshd" || ssh.Username != "root" {
		t.Fatalf("ssh process metadata lost: %+v", ssh)
	}

	// cupsd on 127.0.0.1 → loopback only.
	cups := by["tcp:127.0.0.1:631"]
	if cups.Exposure != ExposureLoopback {
		t.Fatalf("cups exposure=%q, want loopback", cups.Exposure)
	}

	// avahi on ::1 → loopback only (v6).
	avahi := by["udp6:::1:5353"]
	if avahi.Exposure != ExposureLoopback {
		t.Fatalf("avahi exposure=%q, want loopback", avahi.Exposure)
	}
	if avahi.Protocol != ProtoUDP6 {
		t.Fatalf("avahi protocol=%q, want udp6", avahi.Protocol)
	}
}

func TestCollectPropagatesTCPError(t *testing.T) {
	src := &fakeSource{tcpErr: errors.New("perm denied")}
	c := &gopsutilCollector{src: src}
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestCollectSkipsProcessLookupWhenPIDZero(t *testing.T) {
	src := &fakeSource{
		conns: map[string][]Conn{
			"tcp": {{Family: 2, Type: 1, Status: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 80, PID: 0}},
			"udp": {},
		},
		processes: map[int32]struct{ name, exe, user string }{},
	}
	c := &gopsutilCollector{src: src}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 listener, got %d", len(got))
	}
	if got[0].ProcessName != "" || got[0].Exe != "" {
		t.Fatalf("process lookup ran on pid=0: %+v", got[0])
	}
	if src.processCalls != 0 {
		t.Fatalf("ProcessName called %d times for pid=0; should be 0",
			src.processCalls)
	}
}

// -- fakes ------------------------------------------------------------------

type fakeSource struct {
	conns        map[string][]Conn
	processes    map[int32]struct{ name, exe, user string }
	tcpErr       error
	udpErr       error
	processCalls int
}

func (f *fakeSource) Connections(_ context.Context, kind string) ([]Conn, error) {
	if kind == "tcp" && f.tcpErr != nil {
		return nil, f.tcpErr
	}
	if kind == "udp" && f.udpErr != nil {
		return nil, f.udpErr
	}
	return f.conns[kind], nil
}

func (f *fakeSource) ProcessName(_ context.Context, pid int32) (string, string, string) {
	f.processCalls++
	p, ok := f.processes[pid]
	if !ok {
		return "", "", ""
	}
	return p.name, p.exe, p.user
}

// itoa avoids importing strconv just for the by-map key.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
