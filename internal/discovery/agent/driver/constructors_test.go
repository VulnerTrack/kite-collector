package driver

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKmutilShowloaded_DefaultClockIsUTC(t *testing.T) {
	k := NewKmutilShowloaded()
	assert.Equal(t, "/usr/bin/kmutil", k.binary)

	before := time.Now().UTC()
	got := k.now()
	after := time.Now().UTC()
	assert.Equal(t, time.UTC, got.Location(), "collector timestamps must be UTC")
	assert.False(t, got.Before(before))
	assert.False(t, got.After(after))
}

func TestKmutilCollect_NonZeroExitSurfacesError(t *testing.T) {
	bin := writeFakeTool(t, "kmutil", `echo "Error: not entitled" >&2
exit 71
`)
	k := NewKmutilShowloaded()
	k.binary = bin

	res, err := k.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "kmutil showloaded: ")
	assert.Contains(t, err.Error(), "exit status 71")
	assert.Contains(t, err.Error(), "not entitled")
}

func TestNewSystemExtensionsCtl_DefaultClockIsUTC(t *testing.T) {
	s := NewSystemExtensionsCtl()
	assert.Equal(t, "/usr/bin/systemextensionsctl", s.binary)

	before := time.Now().UTC()
	got := s.now()
	after := time.Now().UTC()
	assert.Equal(t, time.UTC, got.Location(), "collector timestamps must be UTC")
	assert.False(t, got.Before(before))
	assert.False(t, got.After(after))
}

func TestParseLOLDriversJSON_Malformed(t *testing.T) {
	t.Parallel()

	entries, err := ParseLOLDriversJSON([]byte(`[{"Id": truncated`))
	require.Error(t, err)
	assert.Nil(t, entries)
	assert.Contains(t, err.Error(), "loldrivers unmarshal")
}

func TestLOLDriversLoader_Load_InvalidURL(t *testing.T) {
	t.Parallel()

	l := NewLOLDriversLoader()
	l.FeedURL = "://not-a-url"
	entries, err := l.Load(context.Background())
	require.Error(t, err)
	assert.Nil(t, entries)
	assert.Contains(t, err.Error(), "loldrivers request")
}

func TestNewLOLDriversLoader_Defaults(t *testing.T) {
	t.Parallel()

	l := NewLOLDriversLoader()
	require.NotNil(t, l.HTTP)
	assert.Equal(t, 30*time.Second, l.HTTP.Timeout)
	assert.Equal(t, LOLDriversFeedURL, l.FeedURL)
	assert.Equal(t, int64(64<<20), l.MaxSize, "body cap must match the RFC-0128 64 MB budget")
}

func TestSysfsBindings_AvailableWithSingleRoot(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("Available is gated on GOOS==linux")
	}

	onlyPCI := &SysfsBindings{
		pciRoot: t.TempDir(),
		usbRoot: "/nonexistent/usb-root",
	}
	assert.True(t, onlyPCI.Available(), "an existing PCI root alone must satisfy Available")

	onlyUSB := &SysfsBindings{
		pciRoot: "/nonexistent/pci-root",
		usbRoot: t.TempDir(),
	}
	assert.True(t, onlyUSB.Available(), "an existing USB root alone must satisfy Available")
}
