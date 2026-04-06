package gobusterparse

type Mode string

const (
	ModeDir   Mode = "dir"
	ModeDNS   Mode = "dns"
	ModeVhost Mode = "vhost"
)

type Record struct {
	Path           string `json:"path"`
	StatusCode     *int   `json:"status_code,omitempty"`
	ResponseLength *int64 `json:"response_length,omitempty"`
}
