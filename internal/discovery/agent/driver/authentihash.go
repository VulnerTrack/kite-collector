package driver

import (
	"crypto"
	_ "crypto/sha1" //#nosec G505 -- legacy Authenticode files only.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// AuthenticodeHash computes the Microsoft Authenticode/PE hash ("Authentihash")
// of a PE/COFF file using SHA-256. The hash is the bytes of the file with the
// following ranges excluded, per the Authenticode spec (Microsoft, 2008
// "Windows Authenticode Portable Executable Signature Format"):
//
//  1. The file checksum field   (OptionalHeader.CheckSum, 4 bytes)
//  2. The Certificate Table     (data directory entry index 4, 8 bytes)
//  3. The signature region      (the bytes between Certificate Table .VA
//     and .VA+.Size — the embedded PKCS#7)
//
// The remaining bytes are streamed through SHA-256 in file order. Returns
// the lowercase hex digest.
func AuthenticodeHash(path string) (string, error) {
	return authenticodeHashWithAlgo(path, crypto.SHA256)
}

// AuthenticodeHashSHA1 returns the legacy SHA-1 Authentihash. Microsoft has
// deprecated SHA-1 catalogs but legacy drivers may still carry only a SHA-1
// signature, so vulnerability matching may need both digests to compare.
func AuthenticodeHashSHA1(path string) (string, error) {
	return authenticodeHashWithAlgo(path, crypto.SHA1)
}

func authenticodeHashWithAlgo(path string, algo crypto.Hash) (string, error) {
	f, err := os.Open(path) //#nosec G304 -- path is caller-resolved driver path
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}

	plan, err := readPEHashPlan(f, info.Size())
	if err != nil {
		return "", err
	}

	if !algo.Available() {
		return "", fmt.Errorf("hash algorithm %v not registered", algo)
	}
	h := algo.New()
	if err := streamHashWithExcluded(f, h, plan); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// peHashPlan captures the byte ranges that must be excluded from the
// Authentihash computation.
type peHashPlan struct {
	checksumOffset           int64 // OptionalHeader.CheckSum byte offset
	certDataDirOffset        int64 // Certificate Table entry within data dirs
	attributeCertificateAddr int64 // file offset of the attribute cert region
	attributeCertificateSize int64 // size in bytes of that region
	totalSize                int64 // file size — used for trailer handling
}

// readPEHashPlan parses the PE/COFF headers far enough to locate the
// CheckSum field and the Certificate Table data directory entry, and
// then reads that entry to find the attribute-certificate region.
func readPEHashPlan(r io.ReaderAt, size int64) (peHashPlan, error) {
	if size < 64 {
		return peHashPlan{}, errors.New("file too small to be a PE")
	}
	dosHeader := make([]byte, 64)
	if _, err := r.ReadAt(dosHeader, 0); err != nil {
		return peHashPlan{}, fmt.Errorf("read DOS header: %w", err)
	}
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return peHashPlan{}, errors.New("not a PE file (missing MZ magic)")
	}
	peOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))
	if peOffset >= size-24 {
		return peHashPlan{}, errors.New("invalid e_lfanew (PE header offset out of range)")
	}

	sig := make([]byte, 4)
	if _, err := r.ReadAt(sig, peOffset); err != nil {
		return peHashPlan{}, fmt.Errorf("read PE signature: %w", err)
	}
	if string(sig) != "PE\x00\x00" {
		return peHashPlan{}, errors.New("missing PE\\0\\0 signature")
	}

	// COFF header is 20 bytes immediately after the PE signature.
	coff := make([]byte, 20)
	if _, err := r.ReadAt(coff, peOffset+4); err != nil {
		return peHashPlan{}, fmt.Errorf("read COFF header: %w", err)
	}
	optHeaderSize := binary.LittleEndian.Uint16(coff[16:18])
	if optHeaderSize == 0 {
		return peHashPlan{}, errors.New("optional header missing")
	}

	optHeaderOffset := peOffset + 4 + 20

	magic := make([]byte, 2)
	if _, err := r.ReadAt(magic, optHeaderOffset); err != nil {
		return peHashPlan{}, fmt.Errorf("read optional header magic: %w", err)
	}

	var checksumOffset int64
	var dataDirOffset int64
	switch m := binary.LittleEndian.Uint16(magic); m {
	case 0x10b: // PE32
		checksumOffset = optHeaderOffset + 64
		dataDirOffset = optHeaderOffset + 96
	case 0x20b: // PE32+
		checksumOffset = optHeaderOffset + 64
		dataDirOffset = optHeaderOffset + 112
	default:
		return peHashPlan{}, fmt.Errorf("unrecognised optional header magic 0x%x", m)
	}

	// Certificate Table is the 5th data directory entry (index 4).
	// Each entry is 8 bytes: 4-byte VA + 4-byte size.
	const certTableIndex = 4
	const dirEntrySize = 8
	certEntryOffset := dataDirOffset + certTableIndex*dirEntrySize

	entry := make([]byte, dirEntrySize)
	if _, err := r.ReadAt(entry, certEntryOffset); err != nil {
		return peHashPlan{}, fmt.Errorf("read certificate table entry: %w", err)
	}
	certVA := int64(binary.LittleEndian.Uint32(entry[0:4]))
	certSize := int64(binary.LittleEndian.Uint32(entry[4:8]))

	return peHashPlan{
		checksumOffset:           checksumOffset,
		certDataDirOffset:        certEntryOffset,
		attributeCertificateAddr: certVA,
		attributeCertificateSize: certSize,
		totalSize:                size,
	}, nil
}

// streamHashWithExcluded writes the file contents to the hash, replacing the
// excluded ranges (CheckSum, Cert Table directory entry, certificate region)
// with no bytes — that is, the ranges are skipped entirely.
//
// The certificate region typically appears at the end of the file. When it
// does, we simply stop streaming once we reach it. When it appears mid-file
// (rare in practice but legal in spec), we skip those bytes and continue.
func streamHashWithExcluded(r io.ReaderAt, w io.Writer, plan peHashPlan) error {
	const bufSize = 64 * 1024

	skips := []byteRange{
		{plan.checksumOffset, 4},
		{plan.certDataDirOffset, 8},
	}
	if plan.attributeCertificateSize > 0 {
		skips = append(skips, byteRange{plan.attributeCertificateAddr, plan.attributeCertificateSize})
	}

	buf := make([]byte, bufSize)
	var off int64
	for off < plan.totalSize {
		toRead := plan.totalSize - off
		if toRead > int64(len(buf)) {
			toRead = int64(len(buf))
		}
		n, err := r.ReadAt(buf[:toRead], off)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read at %d: %w", off, err)
		}
		if n == 0 {
			break
		}
		writeChunkSkipping(w, buf[:n], off, skips)
		off += int64(n)
	}
	return nil
}

// byteRange is an inclusive [start, start+length) span.
type byteRange struct {
	start  int64
	length int64
}

// writeChunkSkipping emits chunk to w, blanking out any bytes that overlap
// with one of the skip ranges. "Blanking" means those bytes are not written
// at all — Authentihash defines them as removed, not zeroed.
func writeChunkSkipping(w io.Writer, chunk []byte, baseOffset int64, skips []byteRange) {
	chunkStart := baseOffset
	chunkEnd := baseOffset + int64(len(chunk))
	cursor := chunkStart

	emit := func(absStart, absEnd int64) {
		if absStart >= absEnd {
			return
		}
		_, _ = w.Write(chunk[absStart-chunkStart : absEnd-chunkStart])
	}

	for {
		next, ok := nextOverlap(skips, cursor, chunkEnd)
		if !ok {
			emit(cursor, chunkEnd)
			return
		}
		emit(cursor, next.start)
		cursor = next.start + next.length
		if cursor >= chunkEnd {
			return
		}
	}
}

// nextOverlap returns the earliest skip range overlapping [from, to).
func nextOverlap(skips []byteRange, from, to int64) (byteRange, bool) {
	var best byteRange
	found := false
	for _, s := range skips {
		end := s.start + s.length
		if end <= from || s.start >= to {
			continue
		}
		clipped := byteRange{
			start:  maxInt64(s.start, from),
			length: 0,
		}
		clippedEnd := minInt64(end, to)
		clipped.length = clippedEnd - clipped.start
		if !found || clipped.start < best.start {
			best = clipped
			found = true
		}
	}
	return best, found
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// guard against the unused-import linter for crypto/sha256 in builds
// that strip the legacy SHA-1 path.
var _ = sha256.New
