package driver

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// elfEhdr and elfShdr mirror the on-disk Elf64 little-endian layouts.
// Field order is the wire format — do not reorder.
type elfEhdr struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type elfShdr struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Off       uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// buildModuleELF constructs a minimal but valid ELF64 relocatable object.
// With withModinfo it carries a .modinfo PROGBITS section holding the given
// NUL-delimited blob — the same shape the kernel build embeds into .ko files.
func buildModuleELF(t *testing.T, modinfo []byte, withModinfo bool) []byte {
	t.Helper()

	var shstr []byte
	if withModinfo {
		shstr = []byte("\x00.modinfo\x00.shstrtab\x00")
	} else {
		shstr = []byte("\x00.shstrtab\x00")
	}

	const ehsize = 64
	buf := &bytes.Buffer{}

	ehdr := elfEhdr{
		Type:      1,  // ET_REL
		Machine:   62, // EM_X86_64
		Version:   1,
		Ehsize:    ehsize,
		Shentsize: 64,
	}
	copy(ehdr.Ident[:], "\x7fELF")
	ehdr.Ident[4] = 2 // ELFCLASS64
	ehdr.Ident[5] = 1 // ELFDATA2LSB
	ehdr.Ident[6] = 1 // EV_CURRENT

	var shdrs []elfShdr
	if withModinfo {
		modinfoOff := uint64(ehsize)
		shstrOff := modinfoOff + uint64(len(modinfo))
		ehdr.Shoff = shstrOff + uint64(len(shstr))
		ehdr.Shnum = 3
		ehdr.Shstrndx = 2
		shdrs = []elfShdr{
			{}, // SHT_NULL
			{Name: 1, Type: 1 /* PROGBITS */, Off: modinfoOff, Size: uint64(len(modinfo)), Addralign: 1},
			{Name: 10, Type: 3 /* STRTAB */, Off: shstrOff, Size: uint64(len(shstr)), Addralign: 1},
		}
	} else {
		shstrOff := uint64(ehsize)
		ehdr.Shoff = shstrOff + uint64(len(shstr))
		ehdr.Shnum = 2
		ehdr.Shstrndx = 1
		shdrs = []elfShdr{
			{},
			{Name: 1, Type: 3 /* STRTAB */, Off: shstrOff, Size: uint64(len(shstr)), Addralign: 1},
		}
	}

	require.NoError(t, binary.Write(buf, binary.LittleEndian, ehdr))
	if withModinfo {
		buf.Write(modinfo)
	}
	buf.Write(shstr)
	for _, sh := range shdrs {
		require.NoError(t, binary.Write(buf, binary.LittleEndian, sh))
	}
	return buf.Bytes()
}

// fakeModinfoBlob is a realistic kernel-module .modinfo payload.
var fakeModinfoBlob = []byte("license=GPL\x00" +
	"version=1.2.3\x00" +
	"description=Fake sound driver\x00" +
	"signer=Acme Corp Kernel Signing Key\x00" +
	"sig_hashalgo=sha512\x00" +
	"depends=snd,ac97_bus\x00" +
	"author=Jane Doe <jane@example.com>\x00")

func writeModuleFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o644)) //#nosec G306 -- fixture
	return path
}

func TestParseModinfo_PlainKO(t *testing.T) {
	t.Parallel()

	path := writeModuleFile(t, "snd_fake.ko", buildModuleELF(t, fakeModinfoBlob, true))
	info, err := ParseModinfo(path)
	require.NoError(t, err)

	assert.Equal(t, "GPL", info["license"])
	assert.Equal(t, "1.2.3", info["version"])
	assert.Equal(t, "Fake sound driver", info["description"])
	assert.Equal(t, "Acme Corp Kernel Signing Key", info["signer"])
	assert.Equal(t, "sha512", info["sig_hashalgo"])
	assert.Equal(t, "snd,ac97_bus", info["depends"])
	assert.Equal(t, "Jane Doe <jane@example.com>", info["author"])
	assert.Len(t, info, 7, "every key=value entry must be decoded exactly once")
}

func TestParseModinfo_GzippedKO(t *testing.T) {
	t.Parallel()

	raw := buildModuleELF(t, fakeModinfoBlob, true)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	path := writeModuleFile(t, "snd_fake.ko.gz", gz.Bytes())
	info, err := ParseModinfo(path)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", info["version"], "gzip-compressed modules must decompress transparently")
}

func TestParseModinfo_CorruptGzip(t *testing.T) {
	t.Parallel()

	path := writeModuleFile(t, "broken.ko.gz", []byte("this is not a gzip stream"))
	info, err := ParseModinfo(path)
	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "gzip reader")
}

func TestParseModinfo_XZAndZstUnsupported(t *testing.T) {
	t.Parallel()

	for name, wantExt := range map[string]string{
		"mod.ko.xz":  `".ko.xz"`,
		"mod.ko.zst": `".ko.zst"`,
	} {
		path := writeModuleFile(t, name, []byte("compressed junk"))
		info, err := ParseModinfo(path)
		require.Error(t, err, name)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "not supported in pure-Go build")
		assert.Contains(t, err.Error(), wantExt,
			"the error must identify which compressed format was found")
	}
}

func TestParseModinfo_NotAnELF(t *testing.T) {
	t.Parallel()

	path := writeModuleFile(t, "garbage.ko", []byte("MZ this is not an ELF"))
	info, err := ParseModinfo(path)
	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "parse ELF")
}

func TestParseModinfo_NoModinfoSection(t *testing.T) {
	t.Parallel()

	path := writeModuleFile(t, "plain.ko", buildModuleELF(t, nil, false))
	info, err := ParseModinfo(path)
	require.Error(t, err)
	assert.Nil(t, info)
	assert.EqualError(t, err, ".modinfo section not present")
}

func TestFilepathExt_Cases(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"/lib/modules/6.1.0/kernel/snd.ko":     ".ko",
		"/lib/modules/6.1.0/kernel/snd.ko.xz":  ".ko.xz",
		"/lib/modules/6.1.0/kernel/snd.ko.zst": ".ko.zst",
		"/lib/modules/6.1.0/kernel/snd.ko.gz":  ".ko.gz",
		"/etc/passwd":                          "",
	}
	for path, want := range cases {
		assert.Equal(t, want, filepathExt(path), path)
	}
}
