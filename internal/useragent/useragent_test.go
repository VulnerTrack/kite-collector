package useragent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func capture(t *testing.T, client *http.Client, set func(*http.Request)) (string, bool) {
	t.Helper()
	var (
		got     string
		present bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["User-Agent"]
		got = r.UserAgent()
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set != nil {
		set(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return got, present
}

func TestWrapStampsVersionedUserAgent(t *testing.T) {
	t.Cleanup(func() { SetVersion("dev") })
	SetVersion("1.2.3")

	client := &http.Client{Transport: Wrap(nil)}
	got, _ := capture(t, client, nil)
	if want := "Kite-collector-http-client/1.2.3"; got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
}

func TestWrapKeepsCallerUserAgent(t *testing.T) {
	client := &http.Client{Transport: Wrap(nil)}
	got, _ := capture(t, client, func(r *http.Request) {
		r.Header.Set("User-Agent", "kite-collector/apifingerprint")
	})
	if got != "kite-collector/apifingerprint" {
		t.Fatalf("User-Agent = %q, want caller's value", got)
	}
}

func TestWrapHonoursExplicitEmptyOptOut(t *testing.T) {
	client := &http.Client{Transport: Wrap(nil)}
	_, present := capture(t, client, func(r *http.Request) {
		r.Header["User-Agent"] = []string{""}
	})
	if present {
		t.Fatal("User-Agent sent despite explicit empty opt-out")
	}
}

func TestWrapDoesNotMutateCallerRequest(t *testing.T) {
	var seen *http.Request
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid", nil)
	resp, err := Wrap(base).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if req.Header.Get("User-Agent") != "" {
		t.Fatal("caller's request was mutated")
	}
	if seen.Header.Get("User-Agent") != String() {
		t.Fatalf("base saw User-Agent %q, want %q", seen.Header.Get("User-Agent"), String())
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	once := Wrap(nil)
	if Wrap(once) != once {
		t.Fatal("re-wrapping stacked a second layer")
	}
}

func TestSetVersionEmptyFallsBackToDev(t *testing.T) {
	t.Cleanup(func() { SetVersion("dev") })
	SetVersion("")
	if got := String(); got != "Kite-collector-http-client/dev" {
		t.Fatalf("String() = %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
