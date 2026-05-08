package gobusterexec

type Mode string

const (
	ModeDir   Mode = "dir"
	ModeDNS   Mode = "dns"
	ModeVhost Mode = "vhost"
)

type Hit struct {
	Mode       Mode     `json:"mode"`
	Path       string   `json:"path"`
	StatusCode *int     `json:"status_code,omitempty"`
	Size       *int64   `json:"size,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Location   string   `json:"location,omitempty"`
	Raw        string   `json:"raw,omitempty"`
}

type RunSummary struct {
	Mode     Mode   `json:"mode"`
	Hits     []Hit  `json:"hits"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}
