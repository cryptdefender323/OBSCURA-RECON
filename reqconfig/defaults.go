package reqconfig

import (
	"math/rand/v2"
)

var DefaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

var WAFBypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"True-Client-IP",
	"Client-IP",
	"X-ProxyUser-Ip",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
	"Forwarded",
	"Base-Url",
	"X-HTTP-Method-Override",
	"Fastly-Client-IP",
	"Akamai-Client-IP",
}

var FakeInternalIPs = []string{
	"10.0.0.1", "10.0.0.2", "10.10.1.1", "10.0.8.1", "10.1.1.1",
	"172.16.0.1", "172.18.0.5", "172.20.10.1",
	"192.168.0.1", "192.168.1.1", "192.168.100.1",
	"1.1.1.1", "8.8.8.8", "8.8.4.4",
	"64.233.160.0", "66.102.0.0", 
	"104.16.0.0", "104.24.0.0", 
}

var OriginSubdomains = []string{
	"direct", "origin", "dev", "stage", "test", "internal", "mail",
	"backend", "api", "vpn", "remote", "ssh", "git", "webmail",
	"m", "preview", "sandbox", "stg", "portal",
}

type BrowserSignature struct {
	UserAgent string
	Headers   map[string]string
}

var ModernBrowserSignatures = []BrowserSignature{
	{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Sec-Ch-Ua":                 `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Sec-Ch-Ua":                 `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"macOS"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
}

var BypassPayloads = []string{
	";",
	"/",
	"//",
	"/./",
	"..;",
	"/.git",
}

func GetBypassHeaders(wafLevel int) map[string]string {
	headers := make(map[string]string)
	if wafLevel <= 0 {
		return headers
	}

	numHeaders := 1
	if wafLevel >= 2 {
		numHeaders = 2 + rand.IntN(3)
	}

	perm := rand.Perm(len(WAFBypassHeaders))
	for i := 0; i < numHeaders && i < len(perm); i++ {
		hdr := WAFBypassHeaders[perm[i]]
		ip := FakeInternalIPs[rand.IntN(len(FakeInternalIPs))]
		headers[hdr] = ip
	}

	return headers
}
