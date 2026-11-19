package models

import "time"

type ScanOptions struct {
	DNSServer   string        `json:"dns_server"`
	UseDoH      bool          `json:"use_doh"`
	DNSAll      bool          `json:"dns_all"`
	CheckIPv6   bool          `json:"check_ipv6"`
	PackageMode bool          `json:"package_mode"`
	ProxyAddr   string        `json:"proxy_addr,omitempty"`
	HTTPMethod  string        `json:"http_method"`
	CompactMode bool          `json:"compact_mode"`
	SpeedTest   bool          `json:"speed_test"`
	TLSAudit    bool          `json:"tls_audit"`
	Timeout     time.Duration `json:"timeout"`
	Ports       []int         `json:"ports"`
	SNI         string        `json:"sni"`
	WSPath      string        `json:"ws_path"`
	ALPN        []string      `json:"alpn"`
	SkipVerify  bool          `json:"skip_verify"`
	CheckASN    bool          `json:"check_asn"`
	CheckRDAP   bool          `json:"check_rdap"`
	BenchCount  int           `json:"bench_count"`
	No302       bool          `json:"no_302"`
	OnlyAlive   bool          `json:"only_alive"`
	Statuses    []int         `json:"statuses,omitempty"`
	RatePerSec  float64       `json:"rate_per_sec,omitempty"`
	Retries     int           `json:"retries,omitempty"`
}

type DNSInfo struct {
	IPv4      []string `json:"ipv4,omitempty"`
	IPv6      []string `json:"ipv6,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
	NS        []string `json:"ns,omitempty"`
	MX        []string `json:"mx,omitempty"`
	TXT       []string `json:"txt,omitempty"`
	Resolver  string   `json:"resolver"`
	ResolveMS int64    `json:"resolve_ms"`
	Error     string   `json:"error,omitempty"`
}

type ASNInfo struct {
	ASN     string `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
	ISP     string `json:"isp,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Error   string `json:"error,omitempty"`
}

type RDAPInfo struct {
	Domain        string `json:"domain,omitempty"`
	Registrar     string `json:"registrar,omitempty"`
	Created       string `json:"created,omitempty"`
	Expires       string `json:"expires,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	Error         string `json:"error,omitempty"`
}

type PortStatus struct {
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type BenchStats struct {
	Port     int     `json:"port"`
	Samples  int     `json:"samples"`
	MinMS    int64   `json:"min_ms"`
	AvgMS    float64 `json:"avg_ms"`
	MaxMS    int64   `json:"max_ms"`
	JitterMS float64 `json:"jitter_ms"`
	LossPct  float64 `json:"loss_pct"`
}

type TLSInfo struct {
	Supported        bool     `json:"supported"`
	Version          string   `json:"version,omitempty"`
	AcceptedVersions []string `json:"accepted_versions,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	NegotiatedALPN   string   `json:"negotiated_alpn,omitempty"`
	SNIUsed          string   `json:"sni_used,omitempty"`
	Issuer           string   `json:"issuer,omitempty"`
	SubjectCN        string   `json:"subject_cn,omitempty"`
	DNSNames         []string `json:"dns_names,omitempty"`
	NotBefore        string   `json:"not_before,omitempty"`
	NotAfter         string   `json:"not_after,omitempty"`
	DaysRemaining    int      `json:"days_remaining,omitempty"`
	HandshakeMS      int64    `json:"handshake_ms,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type SecurityHeadersInfo struct {
	Score   int      `json:"score"`
	Total   int      `json:"total"`
	Present []string `json:"present,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

type HTTPInfo struct {
	Probed          bool                `json:"probed"`
	Method          string              `json:"method,omitempty"`
	Port            int                 `json:"port,omitempty"`
	Scheme          string              `json:"scheme,omitempty"`
	StatusCode      int                 `json:"status_code,omitempty"`
	Server          string              `json:"server,omitempty"`
	HTTP3Quic       bool                `json:"http3_quic"`
	AltSvc          string              `json:"alt_svc,omitempty"`
	SpeedKBps       float64             `json:"speed_kbps,omitempty"`
	DetectedCDN     string              `json:"detected_cdn,omitempty"`
	DetectedWAF     string              `json:"detected_waf,omitempty"`
	RedirectChain   []string            `json:"redirect_chain,omitempty"`
	WebSocket101    bool                `json:"websocket_101"`
	WSStatus        int                 `json:"ws_status,omitempty"`
	SecurityHeaders SecurityHeadersInfo `json:"security_headers"`
	ResponseMS      int64               `json:"response_ms,omitempty"`
	Error           string              `json:"error,omitempty"`
}

type IPv6Status struct {
	Checked   bool   `json:"checked"`
	IP        string `json:"ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	Open      bool   `json:"open"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type ScanResult struct {
	Target       string       `json:"target"`
	Timestamp    string       `json:"timestamp"`
	Alive        bool         `json:"alive"`
	BestIP       string       `json:"best_ip,omitempty"`
	BestLatency  int64        `json:"best_latency_ms,omitempty"`
	CDNHint      string       `json:"cdn_hint,omitempty"`
	TakeoverRisk string       `json:"takeover_risk,omitempty"`
	DNS          DNSInfo      `json:"dns"`
	IPv6         IPv6Status   `json:"ipv6_probe,omitempty"`
	ASN          ASNInfo      `json:"asn"`
	RDAP         RDAPInfo     `json:"rdap"`
	Ports        []PortStatus `json:"ports"`
	Benchmark    BenchStats   `json:"benchmark,omitempty"`
	TLS          TLSInfo      `json:"tls"`
	HTTP         HTTPInfo     `json:"http"`
}
