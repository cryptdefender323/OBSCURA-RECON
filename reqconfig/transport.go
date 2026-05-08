package reqconfig

import (
	"math/rand/v2"
	"net/http"
	"time"
)

func NewRoundTripper(cfg Config) (http.RoundTripper, error) {
	base, err := newBaseTransport(cfg)
	if err != nil {
		return nil, err
	}
	var rt http.RoundTripper = base
	rt = &headerRoundTripper{base: rt, cfg: cfg}
	rt = &delayRoundTripper{base: rt, delay: cfg.Delay, jitter: cfg.Jitter}
	return rt, nil
}

func MustRoundTripper(cfg Config) http.RoundTripper {
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		panic(err)
	}
	return rt
}

func NewClient(cfg Config) (*http.Client, error) {
	rt, err := NewRoundTripper(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: rt,
		Timeout:   cfg.RequestTimeout,
	}, nil
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

var _ HTTPDoer = (*http.Client)(nil)

type delayRoundTripper struct {
	base   http.RoundTripper
	delay  time.Duration
	jitter time.Duration
}

func (d *delayRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if d.base == nil {
		d.base = http.DefaultTransport
	}
	wait := d.delay
	if d.jitter > 0 {
		wait += time.Duration(rand.Int64N(int64(d.jitter) + 1))
	}
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-req.Context().Done():
			t.Stop()
			return nil, req.Context().Err()
		}
		t.Stop()
	}
	return d.base.RoundTrip(req)
}

type headerRoundTripper struct {
	base http.RoundTripper
	cfg  Config
	sig  *BrowserSignature
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.base == nil {
		h.base = http.DefaultTransport
	}
	r2 := req.Clone(req.Context())

	// Implement Consistent Session Identity (V5)
	if h.cfg.WAFBypassLevel >= 2 {
		if h.sig == nil {
			s := ModernBrowserSignatures[rand.IntN(len(ModernBrowserSignatures))]
			h.sig = &s
		}
		r2.Header.Set("User-Agent", h.sig.UserAgent)
		for k, v := range h.sig.Headers {
			r2.Header.Set(k, v)
		}
	} else {
		switch {
		case len(h.cfg.UserAgents) > 0:
			r2.Header.Set("User-Agent", h.cfg.UserAgents[rand.IntN(len(h.cfg.UserAgents))])
		case h.cfg.UserAgent != "":
			r2.Header.Set("User-Agent", h.cfg.UserAgent)
		case r2.Header.Get("User-Agent") == "":
			r2.Header.Set("User-Agent", DefaultUserAgents[rand.IntN(len(DefaultUserAgents))])
		}
	}

	if h.cfg.Headers != nil {
		if h.cfg.OverrideHeaders {
			for k, vals := range h.cfg.Headers {
				r2.Header.Del(k)
				for _, v := range vals {
					r2.Header.Add(k, v)
				}
			}
		} else {
			for k, vals := range h.cfg.Headers {
				if r2.Header.Get(k) != "" {
					continue
				}
				for _, v := range vals {
					r2.Header.Add(k, v)
				}
			}
		}
	}

	if h.cfg.WAFBypassLevel > 0 {
		numHeaders := 2
		if h.cfg.WAFBypassLevel >= 2 {
			numHeaders = 3 + rand.IntN(4)
		}

		perm := rand.Perm(len(WAFBypassHeaders))
		for i := 0; i < numHeaders && i < len(perm); i++ {
			hdr := WAFBypassHeaders[perm[i]]

			if h.cfg.WAFBypassLevel >= 3 && (hdr == "X-Original-URL" || hdr == "X-Rewrite-URL") {
				originalPath := r2.URL.Path
				if r2.URL.RawQuery != "" {
					originalPath += "?" + r2.URL.RawQuery
				}
				r2.Header.Set(hdr, originalPath)

				r2.URL.Path = "/"
				if rand.IntN(2) == 0 {
					r2.URL.Path = "/index.php"
				}
				continue
			}

			if h.cfg.WAFBypassLevel >= 3 && hdr == "X-HTTP-Method-Override" {
				r2.Header.Set(hdr, r2.Method)
				if rand.IntN(2) == 0 {
					r2.Method = "POST"
				}
				continue
			}

			ip := FakeInternalIPs[rand.IntN(len(FakeInternalIPs))]
			r2.Header.Set(hdr, ip)
		}
	}

	return h.base.RoundTrip(r2)
}
