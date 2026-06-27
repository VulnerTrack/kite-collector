package winwer

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseReportDescriptor walks a `Report.wer` body and returns the
// scalar key fields the audit pipeline cares about. WER reports
// are key=value text with one assignment per line; "Sig[N].Name"
// followed by "Sig[N].Value" pairs encode the per-attribute slots
// (application name, version, fault module, etc.) — we collect
// them into a small map first then translate to canonical fields.
//
// The descriptor is typically UTF-16 LE with BOM on Vista+; we
// detect and decode in ParseReportDescriptor's wrapper. UTF-8
// descriptors (older WER, custom-mode reports) pass through.
//
// `report` is mutated in place — the file_hash and any per-dir
// fields stay untouched.
func ParseReportDescriptor(body []byte, report *Report) {
	if len(body) == 0 {
		return
	}
	body = decodeBody(body)
	report.ReportDescriptorHash = HashContents(body)

	sigNames := make(map[string]string, 16)
	sigValues := make(map[string]string, 16)
	dynNames := make(map[string]string, 16)
	dynValues := make(map[string]string, 16)

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(key, "EventType"), strings.EqualFold(key, "EventName"):
			if report.EventName == "" {
				report.EventName = value
			}
		case strings.EqualFold(key, "EventTime"):
			if t := fileTimeToUnix(value); t > 0 {
				report.EventTime = t
			}
		case strings.EqualFold(key, "Consent"):
			report.Consent = value
		case strings.EqualFold(key, "AppPath"):
			report.AppPath = value
			if report.AppName == "" {
				report.AppName = basename(value)
			}
		case strings.EqualFold(key, "AppName"):
			report.AppName = value
		case strings.EqualFold(key, "AppVersion"):
			report.AppVersion = value
		case strings.HasPrefix(key, "Sig[") && strings.HasSuffix(key, ".Name"):
			idx := key[4 : len(key)-len("].Name")]
			sigNames[idx] = value
		case strings.HasPrefix(key, "Sig[") && strings.HasSuffix(key, ".Value"):
			idx := key[4 : len(key)-len("].Value")]
			sigValues[idx] = value
		case strings.HasPrefix(key, "DynamicSig[") && strings.HasSuffix(key, ".Name"):
			idx := key[len("DynamicSig[") : len(key)-len("].Name")]
			dynNames[idx] = value
		case strings.HasPrefix(key, "DynamicSig[") && strings.HasSuffix(key, ".Value"):
			idx := key[len("DynamicSig[") : len(key)-len("].Value")]
			dynValues[idx] = value
		}
	}

	// Walk the Sig[N] pairs and translate to canonical fields.
	for idx, name := range sigNames {
		val := sigValues[idx]
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "application name":
			if report.AppName == "" {
				report.AppName = val
			}
		case "application version":
			if report.AppVersion == "" {
				report.AppVersion = val
			}
		case "fault module name":
			if report.FaultModuleName == "" {
				report.FaultModuleName = val
			}
		case "fault module version":
			if report.FaultModuleVersion == "" {
				report.FaultModuleVersion = val
			}
		}
	}
	// Dynamic sigs occasionally carry OS Version / Locale; not
	// security-relevant on their own. We don't surface them.
	_ = dynNames
	_ = dynValues
}

// splitKV separates `key=value` (no whitespace around `=`).
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]),
			strings.TrimSpace(line[i+1:]),
			true
	}
	return "", "", false
}

// fileTimeToUnix converts a Windows FILETIME (100-nanosecond
// intervals since 1601-01-01 UTC) to a Unix epoch (seconds since
// 1970-01-01 UTC). Returns 0 if the input doesn't parse.
//
// FILETIME → Unix:
//
//	seconds = (filetime / 10000000) - 11644473600
//
// 11644473600 is the number of seconds between 1601-01-01 and
// 1970-01-01.
func fileTimeToUnix(s string) int64 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	const filetimeEpochDiff = 11644473600
	const filetimeTicksPerSec = 10000000
	sec := int64(v/filetimeTicksPerSec) - filetimeEpochDiff
	if sec < 0 {
		return 0
	}
	return sec
}

// decodeBody detects UTF-16 LE / BE BOM and decodes to UTF-8.
// UTF-8 BOM is stripped; bodies without a BOM are returned as-is.
func decodeBody(body []byte) []byte {
	switch {
	case len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF:
		return body[3:]
	case len(body) >= 2 && body[0] == 0xFF && body[1] == 0xFE:
		return utf16LEToUTF8(body[2:])
	case len(body) >= 2 && body[0] == 0xFE && body[1] == 0xFF:
		return utf16BEToUTF8(body[2:])
	}
	return body
}

// utf16LEToUTF8 / utf16BEToUTF8 are minimal in-line decoders that
// trade a bit of speed for zero dependencies (we already pull
// golang.org/x/text in this repo, but keeping winwer self-
// contained is easier on the build). They handle BMP-only
// (no surrogate pairs); WER descriptors are ASCII in practice.
func utf16LEToUTF8(b []byte) []byte {
	out := make([]byte, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := uint16(b[i]) | uint16(b[i+1])<<8
		out = appendUTF8Rune(out, r)
	}
	return out
}

func utf16BEToUTF8(b []byte) []byte {
	out := make([]byte, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := uint16(b[i])<<8 | uint16(b[i+1])
		out = appendUTF8Rune(out, r)
	}
	return out
}

// appendUTF8Rune encodes a BMP code point (uint16) as UTF-8 and
// appends the result. Bytes are masked with 0xFF so gosec can
// see the conversion is in-range.
func appendUTF8Rune(out []byte, r uint16) []byte {
	switch {
	case r < 0x80:
		return append(out, byte(r))
	case r < 0x800:
		return append(out,
			byte((0xC0|r>>6)&0xFF),
			byte((0x80|r&0x3F)&0xFF))
	default:
		return append(out,
			byte((0xE0|r>>12)&0xFF),
			byte((0x80|(r>>6)&0x3F)&0xFF),
			byte((0x80|r&0x3F)&0xFF))
	}
}
