package reqconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func newBaseTransport(cfg Config) (*http.Transport, error) {
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	if cfg.ProxyURL == "" {
		return t, nil
	}

	u, err := url.Parse(cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProxy, err)
	}

	switch u.Scheme {
	case "http", "https":
		t.Proxy = http.ProxyURL(u)
		return t, nil
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidProxy, err)
		}
		t.Proxy = nil
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			t.DialContext = cd.DialContext
			return t, nil
		}
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return dialer.Dial(network, addr)
		}
		return t, nil
	default:
		return nil, fmt.Errorf("%w: scheme %q", ErrInvalidProxy, u.Scheme)
	}
}
