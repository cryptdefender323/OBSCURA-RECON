package reqconfig

var DefaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}

var WAFBypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"True-Client-IP",
	"Cluster-Client-IP",
	"X-ProxyUser-Ip",
	"Forwarded",
}

var FakeInternalIPs = []string{
	"127.0.0.1",
	"10.0.0.1",
	"10.10.1.1",
	"172.16.0.1",
	"192.168.0.1",
	"192.168.1.1",
	"127.0.0.2",
	"localhost",
}

var BypassPayloads = []string{
	";",
	"/",
	"//",
	"/./",
	"..;",
	"/.git",
}
