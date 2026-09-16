package timefmt

import (
	"errors"
	"os"
	"testing"
	"time"
)

var (
	noFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	noLink = func(string) (string, error) { return "", errors.New("not a symlink") }
	fixed  = time.Date(2026, 9, 16, 18, 52, 3, 0, time.UTC)
)

func TestResolvePrefersTZ(t *testing.T) {
	for _, tz := range []string{"America/Tijuana", ":America/Tijuana", " America/Tijuana "} {
		z := resolve(tz, noFile, noLink, fixed)
		if z.name != "America/Tijuana" || z.loc.String() != "America/Tijuana" {
			t.Fatalf("TZ=%q resolved to %q / %v", tz, z.name, z.loc)
		}
	}
}

func TestResolveIgnoresPOSIXRuleStrings(t *testing.T) {
	z := resolve("PST8PDT,M3.2.0,M11.1.0", noFile, noLink, fixed)
	if z.name != "UTC"+fixed.In(time.Local).Format("-07:00") && z.name != "UTC" {
		t.Fatalf("POSIX rule string should fall back to an offset, got %q", z.name)
	}
}

func TestResolveReadsEtcTimezone(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/etc/timezone" {
			return []byte("Europe/Madrid\n"), nil
		}
		return nil, os.ErrNotExist
	}
	z := resolve("", read, noLink, fixed)
	if z.name != "Europe/Madrid" {
		t.Fatalf("got %q", z.name)
	}
}

func TestResolveFollowsLocaltimeSymlink(t *testing.T) {
	cases := map[string]string{
		"/usr/share/zoneinfo/America/Tijuana":       "America/Tijuana",
		"../usr/share/zoneinfo/Asia/Tokyo":          "Asia/Tokyo",
		"/usr/share/zoneinfo/posix/Europe/Berlin":   "Europe/Berlin",
		"/var/db/timezone/zoneinfo/Australia/Perth": "Australia/Perth",
		"/usr/share/zoneinfo/Etc/UTC":               "UTC",
	}
	for target, want := range cases {
		link := func(string) (string, error) { return target, nil }
		z := resolve("", noFile, link, fixed)
		if z.name != want {
			t.Errorf("%s: got %q want %q", target, z.name, want)
		}
	}
}

func TestResolveCanonicalizesLinksViaTzdata(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/usr/share/zoneinfo/tzdata.zi" {
			return []byte("# version 2026a\nZ America/Los_Angeles -7:52:58 - LMT 1883 N 18 20u\nL America/Los_Angeles US/Pacific\nL Etc/UTC UTC\n"), nil
		}
		return nil, os.ErrNotExist
	}
	z := resolve("US/Pacific", read, noLink, fixed)
	if z.name != "America/Los_Angeles" {
		t.Fatalf("link should canonicalize, got %q", z.name)
	}
	if z.loc.String() != "US/Pacific" {
		t.Fatalf("location should still be the loadable name, got %v", z.loc)
	}
	// A canonical name is returned unchanged even when the table is present.
	if z := resolve("Asia/Tokyo", read, noLink, fixed); z.name != "Asia/Tokyo" {
		t.Fatalf("got %q", z.name)
	}
	// UTC stays UTC after the link table maps it to Etc/UTC.
	if z := resolve("UTC", read, noLink, fixed); z.name != "UTC" {
		t.Fatalf("got %q", z.name)
	}
}

func TestResolveFallsBackToOffset(t *testing.T) {
	z := resolve("", noFile, noLink, fixed)
	if z.loc != time.Local {
		t.Fatalf("fallback should render in time.Local, got %v", z.loc)
	}
	_, off := fixed.In(time.Local).Zone()
	want := "UTC"
	if off != 0 {
		want = "UTC" + fixed.In(time.Local).Format("-07:00")
	}
	if z.name != want {
		t.Fatalf("got %q want %q", z.name, want)
	}
}

func TestRenderIncludesZoneName(t *testing.T) {
	loc, err := time.LoadLocation("America/Tijuana")
	if err != nil {
		t.Skip("zoneinfo unavailable")
	}
	z := zone{loc: loc, name: "America/Tijuana"}
	withZone(t, z)

	if got, want := Format(fixed), "2026-09-16 11:52:03 America/Tijuana"; got != want {
		t.Errorf("Format: got %q want %q", got, want)
	}
	if got, want := Date(fixed), "2026-09-16 America/Tijuana"; got != want {
		t.Errorf("Date: got %q want %q", got, want)
	}
	if got, want := Clock(fixed), "11:52 America/Tijuana"; got != want {
		t.Errorf("Clock: got %q want %q", got, want)
	}
	if got := Format(time.Time{}); got != "" {
		t.Errorf("zero time should render empty, got %q", got)
	}
	if ZoneName() != "America/Tijuana" || Location() != loc {
		t.Errorf("accessors disagree with the resolved zone")
	}
}

func TestDateShiftsAcrossMidnight(t *testing.T) {
	loc, err := time.LoadLocation("America/Tijuana")
	if err != nil {
		t.Skip("zoneinfo unavailable")
	}
	withZone(t, zone{loc: loc, name: "America/Tijuana"})
	// 03:00 UTC on the 17th is still the evening of the 16th in Tijuana.
	at := time.Date(2026, 9, 17, 3, 0, 0, 0, time.UTC)
	if got, want := Date(at), "2026-09-16 America/Tijuana"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// withZone pins the package zone for one test and restores lazy resolution
// afterwards.
func withZone(t *testing.T, z zone) {
	t.Helper()
	resolveOnce.Do(func() {})
	prev := resolved
	resolved = z
	t.Cleanup(func() { resolved = prev })
}
