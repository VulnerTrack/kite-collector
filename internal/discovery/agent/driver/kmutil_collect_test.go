package driver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKmutilScript mimics real /usr/bin/kmutil per kmutil(8):
//   - it rejects unknown options such as "--no-symbols" (which does not
//     exist in the man page) with a usage error and exit 1 — the exact
//     failure captured in the field log
//     "kmutil showloaded: wait /usr/bin/kmutil: exit status 1";
//   - for a plain "showloaded" it prints the real-world output shape:
//     a "No variant specified" preamble, a blank line, the column
//     header, then kextstat-style rows.
const fakeKmutilScript = `for a in "$@"; do
  case "$a" in
    showloaded|--list-only) ;;
    *)
      echo "Error: unknown option '$a'" >&2
      exit 1
      ;;
  esac
done
if [ "$1" != "showloaded" ]; then
  echo "Error: missing subcommand" >&2
  exit 1
fi
cat <<'EOF'
No variant specified, falling back to release

Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  135 0                  0          0          com.apple.kpi.bsd (20.1.0) 1BEB2151-70F0-3656-AF8F-9BF853F1F2C1 <>
    9    2 0xffffff800319f000 0xe000     0xe000     com.apple.kec.Libm (1) 7D9632E1-D0E3-347D-A182-003C33041E59 <5>
   84    0 0xffffff7f81234000 0x10000    0x10000    com.apple.driver.AppleAHCIPort (3.4.4) A4EB6B2E-E6FE-3E1C-A0B1-DDA9058D2F31 <5 3 1>
EOF
exit 0
`

// Reproduces the field failure: against a kmutil that faithfully rejects
// options absent from kmutil(8), Collect must still succeed and parse the
// loaded-kext table.
func TestKmutilCollect_AgainstRealCLIBehavior(t *testing.T) {
	bin := writeFakeTool(t, "kmutil", fakeKmutilScript)
	k := &KmutilShowloaded{
		binary: bin,
		now:    func() time.Time { return time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC) },
	}

	res, err := k.Collect(context.Background())
	require.NoError(t, err, "Collect must not invoke kmutil with options that kmutil(8) does not define")
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 3)

	ahci := findByName(res.Drivers, "com.apple.driver.AppleAHCIPort")
	require.NotNil(t, ahci)
	assert.Equal(t, "3.4.4", ahci.Version)
	assert.Equal(t, "Apple", ahci.Vendor)
}

// Real `kmutil showloaded` output opens with a "No variant specified,
// falling back to release" preamble and a blank line before the header.
// The parser must skip the preamble instead of mis-reading it as a
// driver row or recording a parse error.
func TestParseKmutilShowloaded_PreambleSkipped(t *testing.T) {
	t.Parallel()

	raw := "No variant specified, falling back to release\n" +
		"\n" +
		"Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n" +
		"    1  135 0                  0          0          com.apple.kpi.bsd (20.1.0) 1BEB2151-70F0-3656-AF8F-9BF853F1F2C1 <>\n"

	res := ParseKmutilShowloaded(raw)
	require.Empty(t, res.Errs, "preamble lines must not be recorded as parse errors")
	require.Len(t, res.Drivers, 1, "preamble words must not be mis-parsed as driver rows")
	assert.Equal(t, "com.apple.kpi.bsd", res.Drivers[0].Name)
	assert.Equal(t, "20.1.0", res.Drivers[0].Version)
}
