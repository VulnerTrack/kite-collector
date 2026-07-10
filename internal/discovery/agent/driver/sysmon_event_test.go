package driver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSysmonImageLoadEvent_FullDriver(t *testing.T) {
	t.Parallel()
	d := LoadedDriver{
		Name:           "RTCore64.sys",
		DisplayName:    "MSI Afterburner",
		Path:           "C:\\Windows\\System32\\drivers\\RTCore64.sys",
		Version:        "1.0.0.0",
		Vendor:         "MICRO-STAR INTERNATIONAL CO., LTD.",
		Signer:         "MICRO-STAR INTERNATIONAL CO., LTD.",
		SignatureState: SignatureValid,
		Description:    "RTCore64 driver",
		OnDiskSHA256:   "0123456789abcdef",
		Authentihash:   "deadbeef",
		ImportHash:     "feedface",
		CollectedAt:    time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
	}
	ev := SysmonImageLoadEvent(d)
	assert.Equal(t, "6", ev[SysmonAttrEventID])
	assert.Equal(t, "Microsoft-Windows-Sysmon/Operational", ev[SysmonAttrChannel])
	assert.Equal(t, "2026-04-30T12:00:00Z", ev[SysmonAttrUTCTime])
	assert.Equal(t, "C:\\Windows\\System32\\drivers\\RTCore64.sys", ev[SysmonAttrImageLoaded])
	assert.Equal(t, "1.0.0.0", ev[SysmonAttrFileVersion])
	assert.Equal(t, "MSI Afterburner", ev[SysmonAttrProduct])
	assert.Equal(t, "MICRO-STAR INTERNATIONAL CO., LTD.", ev[SysmonAttrCompany])
	assert.Equal(t, "RTCore64.sys", ev[SysmonAttrOriginalName])
	assert.Equal(t, "true", ev[SysmonAttrSigned])
	assert.Equal(t, "MICRO-STAR INTERNATIONAL CO., LTD.", ev[SysmonAttrSignature])
	assert.Equal(t, "Valid", ev[SysmonAttrSignatureStatus])
	assert.Equal(
		t,
		"Authentihash=DEADBEEF,IMPHASH=FEEDFACE,SHA256=0123456789ABCDEF",
		ev[SysmonAttrHashes],
	)
}

func TestSysmonImageLoadEvent_UnsignedLinuxModule(t *testing.T) {
	t.Parallel()
	d := LoadedDriver{
		Name:           "rwdrv",
		Path:           "/lib/modules/rwdrv.ko",
		Version:        "1",
		SignatureState: SignatureUnsigned,
		CollectedAt:    time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
	}
	ev := SysmonImageLoadEvent(d)
	assert.Equal(t, "false", ev[SysmonAttrSigned])
	assert.Equal(t, "Unsigned", ev[SysmonAttrSignatureStatus])
	assert.Empty(t, ev[SysmonAttrSignature])
	assert.Empty(t, ev[SysmonAttrHashes])
	assert.Equal(t, "/lib/modules/rwdrv.ko", ev[SysmonAttrImageLoaded])
}

func TestSysmonImageLoadEvent_PathMissingFallsBackToName(t *testing.T) {
	t.Parallel()
	d := LoadedDriver{
		Name:           "kernel",
		SignatureState: SignatureUnknown,
		CollectedAt:    time.Now().UTC(),
	}
	ev := SysmonImageLoadEvent(d)
	assert.Equal(t, "kernel", ev[SysmonAttrImageLoaded])
	assert.Equal(t, "Unavailable", ev[SysmonAttrSignatureStatus])
}

func TestSysmonImageLoadEvent_SignerFallsBackToVendor(t *testing.T) {
	t.Parallel()
	d := LoadedDriver{
		Name:           "x",
		Vendor:         "Acme",
		SignatureState: SignatureValid,
		CollectedAt:    time.Now().UTC(),
	}
	ev := SysmonImageLoadEvent(d)
	assert.Equal(t, "Acme", ev[SysmonAttrSignature])
	assert.Equal(t, "true", ev[SysmonAttrSigned])
}

func TestSysmonSignatureStatus_AllStatesCovered(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		SignatureValid:    "Valid",
		SignatureCatalog:  "Valid",
		SignatureExpired:  "Expired",
		SignatureRevoked:  "Revoked",
		SignatureUnsigned: "Unsigned",
		SignatureUnknown:  "Unavailable",
		"":                "Unavailable",
		"weird-future":    "Unavailable",
	}
	for in, want := range cases {
		assert.Equal(t, want, SysmonSignatureStatus(in), in)
	}
}

func TestSysmonHashesField_OrderIsStable(t *testing.T) {
	t.Parallel()
	got := sysmonHashesField(LoadedDriver{
		OnDiskSHA256: "abc",
		ImportHash:   "ddd",
		Authentihash: "fff",
	})
	assert.Equal(t, "Authentihash=FFF,IMPHASH=DDD,SHA256=ABC", got)
}

func TestSysmonHashesField_AllEmpty(t *testing.T) {
	t.Parallel()
	assert.Empty(t, sysmonHashesField(LoadedDriver{}))
}

func TestSysmonImageLoadEvent_OmitsBlankOptionalFields(t *testing.T) {
	t.Parallel()
	d := LoadedDriver{
		Name:           "minimal",
		Path:           "/x",
		SignatureState: SignatureUnsigned,
		CollectedAt:    time.Now().UTC(),
	}
	ev := SysmonImageLoadEvent(d)
	_, hasFV := ev[SysmonAttrFileVersion]
	_, hasDesc := ev[SysmonAttrDescription]
	_, hasProduct := ev[SysmonAttrProduct]
	_, hasCompany := ev[SysmonAttrCompany]
	_, hasHashes := ev[SysmonAttrHashes]
	assert.False(t, hasFV)
	assert.False(t, hasDesc)
	assert.False(t, hasProduct)
	assert.False(t, hasCompany)
	assert.False(t, hasHashes)
}
