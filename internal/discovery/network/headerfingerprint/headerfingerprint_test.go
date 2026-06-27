package headerfingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func newDetectorAgainst(t *testing.T, h http.HandlerFunc) (*Detector, *url.URL, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	base, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse: %v", err)
	}
	return NewDetector(srv.Client(), nil), base, srv.Close
}

func TestProbe_DetectsNginx(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "nginx") {
		t.Fatalf("expected nginx, got %+v", res.Fingerprints)
	}
}

func TestProbe_DetectsCloudflareViaCFRay(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "7d0f8c5b6e3c1a2b-LAX")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Server", "cloudflare")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	fp := getProduct(res.Fingerprints, "Cloudflare edge")
	if fp.Vendor == "" {
		t.Fatalf("expected Cloudflare edge, got %+v", res.Fingerprints)
	}
	if fp.Confidence != ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", fp.Confidence)
	}
	if len(fp.Evidence) < 2 {
		t.Fatalf("expected ≥2 evidence entries (CF-Ray + Server), got %v", fp.Evidence)
	}
}

func TestProbe_DetectsVercelViaXVercelId(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Vercel-Id", "iad1::abc123")
		w.Header().Set("X-Vercel-Cache", "MISS")
		w.Header().Set("Server", "Vercel")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "Vercel-hosted") {
		t.Fatalf("expected Vercel-hosted, got %+v", res.Fingerprints)
	}
}

func TestProbe_DetectsPHPAndExpressViaCookies(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "PHPSESSID=abcdef; Path=/")
		w.Header().Add("Set-Cookie", "connect.sid=s%3Aabc.xyz; Path=/")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "PHP") {
		t.Fatalf("expected PHP via PHPSESSID, got %+v", res.Fingerprints)
	}
	if !hasProduct(res.Fingerprints, "Express (Node.js)") {
		t.Fatalf("expected Express via connect.sid, got %+v", res.Fingerprints)
	}
}

func TestProbe_DetectsLaravelLayeredOnNginx(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Add("Set-Cookie", "laravel_session=eyJ...; Path=/")
		w.Header().Add("Set-Cookie", "XSRF-TOKEN=eyJ...; Path=/")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "nginx") {
		t.Fatalf("expected nginx detection alongside Laravel, got %+v", res.Fingerprints)
	}
	if !hasProduct(res.Fingerprints, "Laravel (PHP)") {
		t.Fatalf("expected Laravel via laravel_session, got %+v", res.Fingerprints)
	}
}

func TestProbe_DetectsASPNet(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.Header().Add("Set-Cookie", "ASP.NET_SessionId=xxxxxxxx; HttpOnly")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "IIS") {
		t.Fatalf("expected IIS, got %+v", res.Fingerprints)
	}
	if !hasProduct(res.Fingerprints, "ASP.NET") {
		t.Fatalf("expected ASP.NET, got %+v", res.Fingerprints)
	}
	fp := getProduct(res.Fingerprints, "ASP.NET")
	if len(fp.Evidence) < 2 {
		t.Fatalf("expected ASP.NET to stack evidence, got %v", fp.Evidence)
	}
}

func TestProbe_DetectsDrupalViaXGenerator(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Generator", "Drupal 10 (https://www.drupal.org)")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "Drupal") {
		t.Fatalf("expected Drupal, got %+v", res.Fingerprints)
	}
}

func TestProbe_DetectsHSTSAndCSP(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	if !hasProduct(res.Fingerprints, "HSTS enabled") {
		t.Fatalf("expected HSTS enabled, got %+v", res.Fingerprints)
	}
	if !hasProduct(res.Fingerprints, "Content-Security-Policy enabled") {
		t.Fatalf("expected CSP enabled, got %+v", res.Fingerprints)
	}
}

func TestProbe_NoMatchOnPlainResponse(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	res, _ := d.Probe(context.Background(), base)
	// httptest.Server adds its own Date + Content-Type; nothing
	// should match a known signature.
	if len(res.Fingerprints) != 0 {
		t.Fatalf("expected zero fingerprints, got %+v", res.Fingerprints)
	}
}

func TestExtractCookieNames(t *testing.T) {
	got := ExtractCookieNames([]string{
		"PHPSESSID=abc; Path=/",
		"connect.sid=xyz; HttpOnly",
		"= ignored",
		"JSESSIONID=qqq",
	})
	want := []string{"PHPSESSID", "connect.sid", "JSESSIONID"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cookie[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestMatchPattern_HeaderNamePresence(t *testing.T) {
	h := canonicalHeaders(http.Header{"X-Render-Origin-Server": []string{"render.com"}})
	p := Pattern{Name: "x-render", HeaderName: "X-Render-Origin-Server", Kind: SignalHeaderName, Confidence: ConfidenceHigh}
	ok, ev := MatchPattern(p, h, nil)
	if !ok {
		t.Fatalf("expected presence match")
	}
	if ev == "" {
		t.Fatalf("expected non-empty evidence")
	}
}

func TestMatchPattern_HeaderValueRegex(t *testing.T) {
	h := canonicalHeaders(http.Header{"Server": []string{"nginx/1.24.0"}})
	p := Pattern{
		Name: "server-nginx", HeaderName: "Server",
		ValueRegex: nil, // overridden below
		Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
	}
	for _, sig := range DefaultCatalog() {
		if sig.Product != "nginx" {
			continue
		}
		p = sig.Patterns[0]
	}
	ok, _ := MatchPattern(p, h, nil)
	if !ok {
		t.Fatalf("expected nginx regex match")
	}
}

func TestProbe_NilBaseErrors(t *testing.T) {
	d := NewDetector(nil, nil)
	if _, err := d.Probe(context.Background(), nil); err == nil {
		t.Fatalf("expected error on nil base")
	}
}

func TestProbe_BadSchemeErrors(t *testing.T) {
	d := NewDetector(nil, nil)
	u, _ := url.Parse("ftp://x")
	if _, err := d.Probe(context.Background(), u); err == nil {
		t.Fatalf("expected error on bad scheme")
	}
}

func TestProbe_ContextCancelStopsEarly(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Probe(ctx, base); err == nil {
		t.Fatalf("expected ctx error")
	}
}

func TestProbe_DetectsJSRuntimesAndNextAuth(t *testing.T) {
	cases := []struct {
		product string
		setup   func(w http.ResponseWriter)
	}{
		{
			product: "Bun (runtime)",
			setup: func(w http.ResponseWriter) {
				w.Header().Set("Server", "Bun/1.1.34")
			},
		},
		{
			product: "Deno (runtime / Deploy)",
			setup: func(w http.ResponseWriter) {
				w.Header().Set("Server", "deno/1.45.5")
			},
		},
		{
			product: "Auth.js / NextAuth (session)",
			setup: func(w http.ResponseWriter) {
				w.Header().Add("Set-Cookie", "next-auth.session-token=opaque; HttpOnly; Path=/")
			},
		},
		{
			product: "Auth.js / NextAuth (session)",
			setup: func(w http.ResponseWriter) {
				w.Header().Add("Set-Cookie", "__Secure-next-auth.session-token=opaque; HttpOnly; Path=/; Secure")
			},
		},
		{
			product: "Auth.js / NextAuth (session)",
			setup: func(w http.ResponseWriter) {
				w.Header().Add("Set-Cookie", "authjs.session-token=opaque; HttpOnly; Path=/")
			},
		},
	}
	for i, tc := range cases {
		tc := tc
		t.Run(tc.product, func(t *testing.T) {
			d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				tc.setup(w)
				_, _ = w.Write([]byte("ok"))
			})
			defer stop()
			res, _ := d.Probe(context.Background(), base)
			if !hasProduct(res.Fingerprints, tc.product) {
				t.Fatalf("case[%d] expected %s, got %+v", i, tc.product, res.Fingerprints)
			}
		})
	}
}

func TestDefaultCatalog_AllPatternsValid(t *testing.T) {
	for _, sig := range DefaultCatalog() {
		if sig.Vendor == "" || sig.Product == "" {
			t.Errorf("empty vendor/product: %+v", sig)
		}
		for i, p := range sig.Patterns {
			count := 0
			if p.HeaderName != "" {
				count++
			}
			if p.CookieName != "" {
				count++
			}
			if count != 1 {
				t.Errorf("%s/%s pattern[%d] %q: expected exactly one of HeaderName/CookieName, got %d",
					sig.Vendor, sig.Product, i, p.Name, count)
			}
			if p.Name == "" {
				t.Errorf("%s/%s pattern[%d]: empty name", sig.Vendor, sig.Product, i)
			}
			if p.Confidence == "" {
				t.Errorf("%s/%s pattern[%d] %q: empty confidence", sig.Vendor, sig.Product, i, p.Name)
			}
		}
	}
}

// Helpers

func hasProduct(fps []Fingerprint, product string) bool {
	for _, f := range fps {
		if f.Product == product {
			return true
		}
	}
	return false
}

func getProduct(fps []Fingerprint, product string) Fingerprint {
	for _, f := range fps {
		if f.Product == product {
			return f
		}
	}
	return Fingerprint{}
}
