package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"obscura/reqconfig"
	"strings"
	"time"
)

type OriginResult struct {
	OriginalURL string
	OriginIP    string
	IsBypassed  bool
}

func SeekOrigin(ctx context.Context, targetURL string, reqCfg reqconfig.Config) (*OriginResult, error) {
	result := &OriginResult{OriginalURL: targetURL}

	domain := targetURL
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	targetIPs, _ := net.LookupIP(domain)
	if len(targetIPs) == 0 {
		return result, nil
	}

	refBody, err := fetchReferenceBody(ctx, targetURL)
	if err != nil || len(refBody) < 512 {

		return result, nil
	}
	refTokens := bodyTokenSet(refBody, 4096)

	probeClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	for _, sub := range reqconfig.OriginSubdomains {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		host := fmt.Sprintf("%s.%s", sub, domain)
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			continue
		}

		for _, ip := range ips {

			if ipInList(ip, targetIPs) {
				continue
			}

			directURL := fmt.Sprintf("https://%s", ip.String())
			req, err := http.NewRequestWithContext(ctx, "GET", directURL, nil)
			if err != nil {
				continue
			}
			req.Host = domain

			resp, err := probeClient.Do(req)
			if err != nil {
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			if readErr != nil {
				continue
			}

			if resp.StatusCode != 200 {
				continue
			}

			if len(body) < 512 {
				continue
			}

			candidateTokens := bodyTokenSet(body, 4096)
			if !setsOverlap(refTokens, candidateTokens, 3) {
				continue
			}

			result.OriginIP = ip.String()
			result.IsBypassed = true
			return result, nil
		}
	}

	return result, nil
}

func fetchReferenceBody(ctx context.Context, targetURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
}

func bodyTokenSet(body []byte, maxBytes int) map[string]struct{} {
	if len(body) > maxBytes {
		body = body[:maxBytes]
	}
	tokens := make(map[string]struct{})
	word := make([]byte, 0, 32)
	for _, b := range body {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			if b >= 'A' && b <= 'Z' {
				b += 32 
			}
			word = append(word, b)
		} else {
			if len(word) >= 5 {
				tokens[string(word)] = struct{}{}
			}
			word = word[:0]
		}
	}
	if len(word) >= 5 {
		tokens[string(word)] = struct{}{}
	}
	return tokens
}

func setsOverlap(a, b map[string]struct{}, minCommon int) bool {
	common := 0
	for k := range a {
		if _, ok := b[k]; ok {
			common++
			if common >= minCommon {
				return true
			}
		}
	}
	return false
}

func ipInList(ip net.IP, list []net.IP) bool {
	for _, x := range list {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}
