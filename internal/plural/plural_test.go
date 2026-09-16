package plural

import "testing"

func TestCount(t *testing.T) {
	cases := map[string]string{
		Count(0, "machine"):              "0 machines",
		Count(1, "machine"):              "1 machine",
		Count(2, "machine"):              "2 machines",
		CountWith(1, "entry", "entries"): "1 entry",
		CountWith(3, "entry", "entries"): "3 entries",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
