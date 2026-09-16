// Package timefmt renders timestamps for humans: the CLI's text output and the
// dashboard's HTML. Every rendered value names its zone, and the zone is the
// host's IANA identifier ("America/Tijuana") rather than an abbreviation
// ("PDT" is ambiguous, "MST" doubles as Go's layout token) or a bare offset.
//
// Machine-facing output (JSON, CSV, filenames) is not this package's business:
// RFC 3339 already carries the offset and consumers parse it.
//
// Resolution order for the zone name, first hit wins:
//
//  1. $TZ when it names a loadable zone ("America/Tijuana", ":America/Tijuana").
//  2. /etc/timezone (Debian-family hosts write the IANA name there).
//  3. The /etc/localtime symlink target, relative to a zoneinfo directory
//     (Linux, macOS, the BSDs).
//
// A resolved name that is a backward-compatibility link ("US/Pacific") is
// mapped to its canonical zone ("America/Los_Angeles") through the tzdata
// link table (tzdata.zi) when the host ships one.
//
// When none resolves (Windows has no IANA mapping in the standard library, or
// /etc/localtime is a regular file) the zone falls back to time.Local and the
// name to a UTC offset such as "UTC-07:00", which still states the zone even
// though it cannot name it.
package timefmt

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	layoutDateTime = "2006-01-02 15:04:05"
	layoutDate     = "2006-01-02"
	layoutClock    = "15:04"
)

// zoneinfoDirs are the roots an /etc/localtime symlink is resolved against,
// in the order the common platforms lay them out.
var zoneinfoDirs = []string{
	"/usr/share/zoneinfo/",
	"/usr/lib/zoneinfo/",
	"/usr/share/lib/zoneinfo/",
	"/var/db/timezone/zoneinfo/",
	"/etc/zoneinfo/",
}

type zone struct {
	loc  *time.Location
	name string
}

var (
	resolveOnce sync.Once
	resolved    zone
)

// Location returns the zone every helper in this package renders in.
func Location() *time.Location {
	return current().loc
}

// ZoneName returns the IANA identifier of the host zone, or a UTC offset when
// the host cannot name it.
func ZoneName() string {
	return current().name
}

// Format renders a timestamp as "2006-01-02 15:04:05 <zone>". A zero time
// renders as an empty string so templates can test it without a helper.
func Format(t time.Time) string {
	return render(t, layoutDateTime)
}

// Date renders the calendar date as "2006-01-02 <zone>". The zone still
// matters: a certificate that expires at 03:00 UTC expires the previous
// evening in the Americas.
func Date(t time.Time) string {
	return render(t, layoutDate)
}

// Clock renders the time of day as "15:04 <zone>".
func Clock(t time.Time) string {
	return render(t, layoutClock)
}

func render(t time.Time, layout string) string {
	if t.IsZero() {
		return ""
	}
	z := current()
	return t.In(z.loc).Format(layout) + " " + z.name
}

func current() zone {
	resolveOnce.Do(func() {
		resolved = resolve(os.Getenv("TZ"), os.ReadFile, os.Readlink, time.Now())
	})
	return resolved
}

// resolve is the pure core of current(): it takes the inputs that vary by
// host so tests can drive every branch without touching the process zone.
func resolve(
	tzEnv string,
	readFile func(string) ([]byte, error),
	readlink func(string) (string, error),
	now time.Time,
) zone {
	named := func(name string) (zone, bool) {
		loc, err := time.LoadLocation(name)
		if err != nil {
			return zone{}, false
		}
		return zone{loc: loc, name: normalize(canonical(name, readFile))}, true
	}
	if name, ok := zoneFromTZ(tzEnv); ok {
		if z, ok := named(name); ok {
			return z
		}
	}
	if raw, err := readFile("/etc/timezone"); err == nil {
		if name := strings.TrimSpace(string(raw)); name != "" {
			if z, ok := named(name); ok {
				return z
			}
		}
	}
	if target, err := readlink("/etc/localtime"); err == nil {
		if name, ok := zoneFromLocaltime(target); ok {
			if z, ok := named(name); ok {
				return z
			}
		}
	}
	return zone{loc: time.Local, name: offsetName(now.In(time.Local))}
}

// canonical follows a backward-compatibility link ("US/Pacific") to the zone
// it points at ("America/Los_Angeles") using the tzdata link table. The table
// is the "L <target> <link>" lines of tzdata.zi, which tzdata installs next to
// the zone files; without it the name is returned unchanged.
func canonical(name string, readFile func(string) ([]byte, error)) string {
	for _, dir := range zoneinfoDirs {
		raw, err := readFile(dir + "tzdata.zi")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "L ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[2] == name {
				return fields[1]
			}
		}
		return name
	}
	return name
}

// zoneFromTZ extracts an IANA name from a POSIX TZ value. A leading colon is
// the "file name follows" marker; anything with a slash or a plain "UTC" is
// treated as a name, while POSIX rule strings ("PST8PDT,M3.2.0,M11.1.0") are
// not names and are skipped.
func zoneFromTZ(v string) (string, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(v, ":"))
	if v == "" {
		return "", false
	}
	if v == "UTC" || strings.Contains(v, "/") {
		return v, true
	}
	return "", false
}

// zoneFromLocaltime turns a symlink target such as
// "/usr/share/zoneinfo/America/Tijuana" or "../usr/share/zoneinfo/UTC" into
// the IANA name that follows the zoneinfo root.
func zoneFromLocaltime(target string) (string, bool) {
	t := filepath.ToSlash(target)
	for _, dir := range zoneinfoDirs {
		if i := strings.Index(t, dir); i >= 0 {
			name := t[i+len(dir):]
			// Skip the "posix/" and "right/" mirrors of the database.
			name = strings.TrimPrefix(strings.TrimPrefix(name, "posix/"), "right/")
			if name != "" {
				return name, true
			}
		}
	}
	return "", false
}

// normalize collapses the aliases of UTC to the plain name people expect; a
// host that really runs on UTC should say so rather than "Etc/UTC".
func normalize(name string) string {
	switch name {
	case "Etc/UTC", "Etc/Universal", "Etc/Zulu", "Universal", "Zulu", "UCT", "Etc/UCT":
		return "UTC"
	}
	return name
}

// offsetName renders the zone as "UTC-07:00" when no IANA name is available;
// UTC itself renders as "UTC".
func offsetName(t time.Time) string {
	_, off := t.Zone()
	if off == 0 {
		return "UTC"
	}
	return "UTC" + t.Format("-07:00")
}
