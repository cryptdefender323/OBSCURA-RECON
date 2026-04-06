package reqconfig

import (
	"net/http"
	"time"
)

type Config struct {
	Delay time.Duration

	Jitter time.Duration

	Headers http.Header

	OverrideHeaders bool

	UserAgents []string

	UserAgent string

	ProxyURL string

	InsecureSkipVerify bool

	RequestTimeout time.Duration

	WAFBypassLevel int

	MethodProbing bool
}

func (c Config) Clone() Config {
	out := c
	if c.Headers != nil {
		out.Headers = c.Headers.Clone()
	}
	if len(c.UserAgents) > 0 {
		out.UserAgents = append([]string(nil), c.UserAgents...)
	}
	return out
}
