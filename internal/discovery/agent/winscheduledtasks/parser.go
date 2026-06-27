package winscheduledtasks

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// rawTask mirrors the XML shape Task Scheduler emits. encoding/xml
// pulls field names from `xml:""` tags; namespaces are stripped
// because the parser is invoked with strict=false (Apple-shipped
// XML occasionally drops the xmlns attribute).
type rawTask struct {
	XMLName          xml.Name        `xml:"Task"`
	RegistrationInfo rawRegistration `xml:"RegistrationInfo"`
	Principals       rawPrincipals   `xml:"Principals"`
	Settings         rawSettings     `xml:"Settings"`
	Triggers         rawTriggers     `xml:"Triggers"`
	Actions          rawActions      `xml:"Actions"`
}

type rawRegistration struct {
	Author      string `xml:"Author"`
	Description string `xml:"Description"`
	Date        string `xml:"Date"`
	URI         string `xml:"URI"`
}

type rawPrincipals struct {
	Principal []rawPrincipal `xml:"Principal"`
}

type rawPrincipal struct {
	ID        string `xml:"id,attr"`
	UserID    string `xml:"UserId"`
	GroupID   string `xml:"GroupId"`
	RunLevel  string `xml:"RunLevel"`
	LogonType string `xml:"LogonType"`
}

type rawSettings struct {
	Enabled string `xml:"Enabled"`
	Hidden  string `xml:"Hidden"`
}

type rawTriggers struct {
	InnerXML string `xml:",innerxml"`
}

type rawActions struct {
	Exec []rawExec `xml:"Exec"`
}

type rawExec struct {
	Command          string `xml:"Command"`
	Arguments        string `xml:"Arguments"`
	WorkingDirectory string `xml:"WorkingDirectory"`
}

// ParseTaskXML walks a single Windows Task XML body and returns a
// populated Task. The body is typically UTF-16 LE with BOM (Task
// Scheduler's native serialization); we decode to UTF-8 first.
//
// `taskPath` is the canonical Task Scheduler path the file lives at
// — derived by the collector from the relative path under
// C:\Windows\System32\Tasks\.
func ParseTaskXML(body []byte, filePath, taskPath string) (Task, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return Task{}, fmt.Errorf("empty task XML")
	}
	utf8Body, err := decodeToUTF8(body)
	if err != nil {
		return Task{}, fmt.Errorf("decode task XML: %w", err)
	}

	dec := xml.NewDecoder(bytes.NewReader(utf8Body))
	// Task XML always declares a default namespace; encoding/xml's
	// strict mode requires struct tags to specify it. Disable strict
	// + ignore the namespace and let the bare element names match.
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	var raw rawTask
	if err := dec.Decode(&raw); err != nil {
		return Task{}, fmt.Errorf("unmarshal task XML: %w", err)
	}

	out := Task{
		FilePath:         filePath,
		FileHash:         HashContents(body),
		TaskPath:         taskPath,
		TaskName:         leafName(taskPath),
		Author:           strings.TrimSpace(raw.RegistrationInfo.Author),
		Description:      strings.TrimSpace(raw.RegistrationInfo.Description),
		RegistrationDate: strings.TrimSpace(raw.RegistrationInfo.Date),
		URI:              strings.TrimSpace(raw.RegistrationInfo.URI),
		IsEnabled: IsBoolTrue(raw.Settings.Enabled) ||
			strings.TrimSpace(raw.Settings.Enabled) == "",
		// Task Scheduler's "Enabled" defaults to true when the element
		// is absent — every shipped Microsoft task relies on that.
		IsHidden: IsBoolTrue(raw.Settings.Hidden),
	}

	// Principal: prefer the first <Principal> entry. Multi-principal
	// tasks are uncommon and the Action's `Context` attribute would
	// select between them — we don't currently model that.
	if len(raw.Principals.Principal) > 0 {
		p := raw.Principals.Principal[0]
		out.PrincipalUserID = strings.TrimSpace(p.UserID)
		out.PrincipalGroupID = strings.TrimSpace(p.GroupID)
		out.RunLevel = strings.TrimSpace(p.RunLevel)
		out.LogonType = strings.TrimSpace(p.LogonType)
	}

	out.Triggers = extractTriggerNames(raw.Triggers.InnerXML)
	for _, e := range raw.Actions.Exec {
		out.Actions = append(out.Actions, Action{
			Kind:             "Exec",
			Command:          strings.TrimSpace(e.Command),
			Arguments:        strings.TrimSpace(e.Arguments),
			WorkingDirectory: strings.TrimSpace(e.WorkingDirectory),
		})
	}

	AnnotateSecurity(&out)
	return out, nil
}

// decodeToUTF8 detects UTF-16 BOM (LE / BE) and decodes via x/text.
// UTF-8 BOM is stripped; bodies without a BOM are returned as-is.
func decodeToUTF8(body []byte) ([]byte, error) {
	switch {
	case len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF:
		return body[3:], nil
	case len(body) >= 2 && body[0] == 0xFF && body[1] == 0xFE:
		dec := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
		out, _, err := transform.Bytes(dec, body)
		if err != nil {
			return nil, fmt.Errorf("utf16-le decode: %w", err)
		}
		return out, nil
	case len(body) >= 2 && body[0] == 0xFE && body[1] == 0xFF:
		dec := unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewDecoder()
		out, _, err := transform.Bytes(dec, body)
		if err != nil {
			return nil, fmt.Errorf("utf16-be decode: %w", err)
		}
		return out, nil
	}
	return body, nil
}

// extractTriggerNames walks the inner XML of <Triggers> and returns
// the local names of every top-level child element. Tasks emit
// <LogonTrigger>, <BootTrigger>, <IdleTrigger>, <CalendarTrigger>,
// <EventTrigger>, <RegistrationTrigger>, <SessionStateChangeTrigger>,
// and <TimeTrigger>. We don't currently introspect their contents —
// the presence alone is the audit signal.
func extractTriggerNames(innerXML string) []string {
	if strings.TrimSpace(innerXML) == "" {
		return nil
	}
	out := make([]string, 0, 4)
	dec := xml.NewDecoder(strings.NewReader(innerXML))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		if start, ok := tok.(xml.StartElement); ok {
			out = append(out, start.Name.Local)
			// Skip past the matching close tag so we don't double-count
			// nested elements.
			if err := dec.Skip(); err != nil {
				return out
			}
		}
	}
	return out
}

// leafName returns the last component of a Task Scheduler path. The
// path uses backslashes per Windows convention (`\Microsoft\Windows\
// AppID\PolicyConverter` → `PolicyConverter`).
func leafName(taskPath string) string {
	if taskPath == "" {
		return ""
	}
	if i := strings.LastIndex(taskPath, `\`); i >= 0 {
		return taskPath[i+1:]
	}
	return taskPath
}
