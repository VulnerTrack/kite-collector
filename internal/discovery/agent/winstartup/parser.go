package winstartup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Shell-Link (.lnk) binary layout — MS-SHLLINK §2.1, .2, .3:
//
//	ShellLinkHeader     76 bytes (fixed)
//	  HeaderSize        4 bytes  (== 0x0000004C)
//	  LinkCLSID         16 bytes
//	  LinkFlags         4 bytes (uint32 LE) at offset 0x14
//	  FileAttributes    4 bytes
//	  CreationTime      8 bytes
//	  AccessTime        8 bytes
//	  WriteTime         8 bytes
//	  FileSize          4 bytes
//	  IconIndex         4 bytes
//	  ShowCommand       4 bytes
//	  HotKey            2 bytes
//	  Reserved          10 bytes
//	[optional LinkTargetIDList] if HasLinkTargetIDList (LinkFlags bit 0)
//	  IDListSize        2 bytes (uint16 LE)
//	  IDList            IDListSize bytes
//	[optional LinkInfo] if HasLinkInfo (LinkFlags bit 1)
//	  LinkInfoSize             4 bytes
//	  LinkInfoHeaderSize       4 bytes
//	  LinkInfoFlags            4 bytes (bit 0 = VolumeIDAndLocalBasePath)
//	  VolumeIDOffset           4 bytes
//	  LocalBasePathOffset      4 bytes (only meaningful if bit 0)
//	  CommonNetworkRelativeLinkOffset 4 bytes
//	  CommonPathSuffixOffset   4 bytes
//	  [if LinkInfoHeaderSize >= 0x24] LocalBasePathOffsetUnicode 4 bytes
//	  ... blobs ...
//
// We only extract the LocalBasePath (ANSI or Unicode variant). The
// rest of the format is irrelevant to the audit use case.
const shellLinkHeaderSize = 76

// Shell-Link LinkFlags bits we care about.
const (
	flagHasLinkTargetIDList = 1 << 0
	flagHasLinkInfo         = 1 << 1
)

// LinkInfoFlags bits.
const (
	linkInfoFlagVolumeIDAndLocalBasePath = 1 << 0
)

// ParseShellLinkTarget walks a .lnk body and returns the resolved
// LocalBasePath (e.g. `C:\Program Files\Foo\foo.exe`) when the
// link carries a LinkInfo block with a local base path. Returns
// the empty string + a nil error when the link uses a non-local
// target (network share without a local path, IDList-only links).
//
// Best-effort: any parse error returns "" + the error so callers
// can record the bytes but skip target_path.
func ParseShellLinkTarget(body []byte) (string, error) {
	if len(body) < shellLinkHeaderSize {
		return "", fmt.Errorf("short body: %d bytes", len(body))
	}
	if binary.LittleEndian.Uint32(body[0:4]) != shellLinkHeaderSize {
		return "", errors.New("invalid header size")
	}
	flags := binary.LittleEndian.Uint32(body[0x14:0x18])

	offset := shellLinkHeaderSize

	// Skip LinkTargetIDList if present.
	if flags&flagHasLinkTargetIDList != 0 {
		if offset+2 > len(body) {
			return "", errors.New("truncated IDList size")
		}
		idListSize := int(binary.LittleEndian.Uint16(body[offset : offset+2]))
		offset += 2 + idListSize
	}

	// LinkInfo block.
	if flags&flagHasLinkInfo == 0 {
		return "", nil
	}
	if offset+0x1C > len(body) {
		return "", errors.New("truncated LinkInfo header")
	}
	linkInfoStart := offset
	linkInfoSize := int(binary.LittleEndian.Uint32(body[offset : offset+4]))
	linkInfoHeaderSize := int(binary.LittleEndian.Uint32(body[offset+4 : offset+8]))
	linkInfoFlags := binary.LittleEndian.Uint32(body[offset+8 : offset+12])
	if linkInfoFlags&linkInfoFlagVolumeIDAndLocalBasePath == 0 {
		return "", nil
	}
	// Bounds check the whole LinkInfo block.
	if linkInfoStart+linkInfoSize > len(body) {
		return "", errors.New("LinkInfo size overflows body")
	}

	// LocalBasePathOffset is at LinkInfo + 0x10. The Unicode
	// variant LocalBasePathOffsetUnicode lives at LinkInfo + 0x1C
	// and is only present when LinkInfoHeaderSize >= 0x24.
	localBasePathOffset := int(binary.LittleEndian.Uint32(body[offset+0x10 : offset+0x14]))
	hasUnicode := linkInfoHeaderSize >= 0x24

	if hasUnicode && offset+0x20 <= len(body) {
		unicodeOffset := int(binary.LittleEndian.Uint32(body[offset+0x1C : offset+0x20]))
		if unicodeOffset > 0 {
			abs := linkInfoStart + unicodeOffset
			if abs < len(body) {
				return readUTF16NullTerminated(body[abs:])
			}
		}
	}
	if localBasePathOffset > 0 {
		abs := linkInfoStart + localBasePathOffset
		if abs < len(body) {
			return readANSINullTerminated(body[abs:]), nil
		}
	}
	return "", nil
}

// readANSINullTerminated returns the ANSI string up to the first
// 0 byte (or end-of-buffer).
func readANSINullTerminated(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// readUTF16NullTerminated decodes a UTF-16LE string up to the
// first U+0000 (or end-of-buffer if no terminator is present).
func readUTF16NullTerminated(b []byte) (string, error) {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	end := len(b)
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			end = i
			break
		}
	}
	u16 := make([]uint16, end/2)
	for i := 0; i < end; i += 2 {
		u16[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
	}
	return string(utf16.Decode(u16)), nil
}
