package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCSVRows(t *testing.T) {
	rows, err := parseCSVRows([]byte("Node,Name,Version\r\nPC,Example,1.2\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["Name"] != "Example" || rows[0]["Version"] != "1.2" {
		t.Fatalf("unexpected rows: %#v", rows)
	}
}

func TestParseRegistryRowsRedactsSensitiveValues(t *testing.T) {
	rows := parseRegistryRows([]byte(strings.Join([]string{
		`HKEY_LOCAL_MACHINE\Software\Example`,
		`    DisplayName    REG_SZ    Safe Application`,
		`    ApiToken       REG_SZ    must-not-survive`,
	}, "\r\n")))
	if len(rows) != 2 {
		t.Fatalf("unexpected rows: %#v", rows)
	}
	if rows[0]["value"] != "[REDACTED]" && rows[1]["value"] != "[REDACTED]" {
		t.Fatalf("sensitive registry value was not redacted: %#v", rows)
	}
}

func TestDecodeWindowsOutputCP850(t *testing.T) {
	// "Dirección" as emitted by a Spanish CP850 console.
	decoded := string(decodeWindowsOutput([]byte{'D', 'i', 'r', 'e', 'c', 'c', 'i', 0xa2, 'n'}))
	if decoded != "Dirección" {
		t.Fatalf("decoded=%q", decoded)
	}
}

func TestParseInstalledApplicationsGroupsRegistryValues(t *testing.T) {
	rows := parseInstalledApplications([]byte(strings.Join([]string{
		`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\App1`,
		`    DisplayName    REG_SZ    Example App`,
		`    DisplayVersion REG_SZ    1.2.3`,
		`    Publisher      REG_SZ    Example Corp`,
		`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\NoDisplayName`,
		`    DisplayVersion REG_SZ    9`,
	}, "\r\n")), "native")
	if len(rows) != 1 || rows[0]["name"] != "Example App" || rows[0]["version"] != "1.2.3" {
		t.Fatalf("unexpected applications: %#v", rows)
	}
}

func TestInventoryDatabaseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := inventorySnapshot{
		CollectedAt: time.Now().UTC().Truncate(time.Nanosecond),
		Hostname:    "ROBERTO-PC",
		Categories: map[string][]map[string]string{
			"software": {{"name": "Kite", "version": "1"}},
		},
	}
	if err := saveInventory(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadLatestInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != want.Hostname || len(got.Categories["software"]) != 1 {
		t.Fatalf("unexpected snapshot: %#v", got)
	}
	rows, err := loadInventoryCategory(dir, "software")
	if err != nil || rows[0]["name"] != "Kite" {
		t.Fatalf("unexpected category: %#v, %v", rows, err)
	}
}

func TestInventoryHistoryAndDashboard(t *testing.T) {
	dir := t.TempDir()
	first := inventorySnapshot{
		CollectedAt: time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC),
		Hostname:    "ROBERTO-PC",
		Categories: map[string][]map[string]string{
			"system":                    {{"Host Name": "ROBERTO-PC"}},
			"installed_software_native": {{"name": "Kite", "version": "1"}},
			"services":                  {{"Name": "kite-collector-legacy"}},
		},
	}
	second := first
	second.CollectedAt = first.CollectedAt.Add(time.Hour)
	second.Categories = map[string][]map[string]string{
		"system":                    {{"Host Name": "ROBERTO-PC"}},
		"installed_software_native": {{"name": "Kite", "version": "1"}, {"name": "Example", "version": "2"}},
		"services":                  {{"Name": "kite-collector-legacy"}},
	}
	if err := saveInventory(dir, first); err != nil {
		t.Fatal(err)
	}
	if err := saveInventory(dir, second); err != nil {
		t.Fatal(err)
	}
	history, err := loadInventoryHistory(dir, 30)
	if err != nil || len(history) != 2 {
		t.Fatalf("history=%#v err=%v", history, err)
	}
	changes := compareSnapshots(&history[0], &history[1])
	if len(changes) != 1 || changes[0].Category != "installed_software_native" || changes[0].Delta != 1 {
		t.Fatalf("unexpected changes: %#v", changes)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?category=installed_software_native", nil)
	(&legacyDashboard{dir: dir}).serveHome(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, expected := range []string{"ROBERTO-PC", "Installed software", "Example", "Changes since previous scan", "Download kite.db"} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("dashboard missing %q", expected)
		}
	}
}

func TestBuildInventoryOTLPRecordsIncludesSummaryAndEveryCategory(t *testing.T) {
	snapshot := &inventorySnapshot{
		CollectedAt: time.Date(2026, 8, 12, 5, 0, 0, 0, time.UTC),
		Hostname:    "ROBERTO-PC",
		Categories: map[string][]map[string]string{
			"operating_system":          {{"Version": "6.1.7601", "Caption": "Windows 7"}},
			"services":                  {{"Name": "kite-collector-legacy", "State": "Running"}},
			"installed_software_native": {{"name": "Example", "publisher": "Vendor", "version": "1.2"}},
		},
		Errors: map[string]string{"bitlocker": "not supported"},
	}
	resource := mapOTLPAttributes(map[string]string{
		"agent.id": "11111111-1111-5111-8111-111111111111",
	})
	records, err := buildInventoryOTLPRecords(snapshot, resource)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 { // one summary + three categories + one error category
		t.Fatalf("record count=%d", len(records))
	}
	if records[0].EventName != "kite.machine.updated" {
		t.Fatalf("summary event=%q", records[0].EventName)
	}
	attrs := make(map[string]string)
	for _, attr := range records[1].Attributes {
		if attr.Value.StringValue != nil {
			attrs[attr.Key] = *attr.Value.StringValue
		}
	}
	if attrs["event_type"] != "WindowsInventoryCategory" || attrs["event.name"] != "machine.changed" {
		t.Fatalf("unexpected category attributes: %#v", attrs)
	}
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(*records[1].Body.StringValue), &body); err != nil {
		t.Fatal(err)
	}
	if body["asset_id"] == "" || body["category"] == "" {
		t.Fatalf("incomplete category body: %#v", body)
	}
}

func TestInventorySyncWatermark(t *testing.T) {
	dir := t.TempDir()
	collectedAt := time.Date(2026, 8, 12, 5, 30, 0, 123, time.UTC)
	if err := saveInventory(dir, inventorySnapshot{CollectedAt: collectedAt, Categories: map[string][]map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	needed, err := inventoryNeedsSync(dir, collectedAt)
	if err != nil || !needed {
		t.Fatalf("needed=%v err=%v", needed, err)
	}
	if err := markInventorySynced(dir, collectedAt); err != nil {
		t.Fatal(err)
	}
	needed, err = inventoryNeedsSync(dir, collectedAt)
	if err != nil || needed {
		t.Fatalf("needed=%v err=%v", needed, err)
	}
}
