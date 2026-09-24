// inhive_option.go — InhiveOptions struct with all VPN configuration parameters.
package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type InhiveOptions struct {
	EnableFullConfig        bool   `json:"enable-full-config,omitempty" overridable:"true"`
	LogLevel                string `json:"log-level,omitempty"`
	LogFile                 string `json:"log-file,omitempty"`
	EnableClashApi          bool   `json:"enable-clash-api,omitempty"`
	ClashApiPort            uint16 `json:"clash-api-port,omitempty"`
	ClashApiSecret          string `json:"web-secret,omitempty"`
	Region                  string `json:"region,omitempty"`
	BlockAds                bool   `json:"block-ads,omitempty" overridable:"true"`
	UseXrayCoreWhenPossible bool   `json:"use-xray-core-when-possible,omitempty" overridable:"true"`
	BalancerStrategy        string `json:"balancer-strategy,omitempty" overridable:"true"`
	// GeoIPPath        string      `json:"geoip-path"`
	// GeoSitePath      string      `json:"geosite-path"`
	Rules     []Rule      `json:"rules,omitempty" overridable:"true"`
	Warp      WarpOptions `json:"warp,omitempty"`
	Warp2     WarpOptions `json:"warp2,omitempty"`
	Mux       MuxOptions  `json:"mux,omitempty" overridable:"true"`
	TLSTricks TLSTricks   `json:"tls-tricks,omitempty"`
	EnableNTP bool        `json:"enable-ntp,omitempty"`

	// DAITA — Defence Against Traffic Analysis.
	// When enabled, wraps all outbound TCP connections with maybenot padding injection.
	DaitaEnabled  bool    `json:"daita-enabled,omitempty"`
	DaitaMachines string  `json:"daita-machines,omitempty"` // LF-separated base64 machine strings
	DaitaMaxPad   float64 `json:"daita-max-pad,omitempty"`  // fraction of bandwidth for padding (0-1)

	DNSOptions
	InboundOptions
	URLTestOptions
	RouteOptions
}

type DNSOptions struct {
	RemoteDnsAddress        string                `json:"remote-dns-address,omitempty" overridable:"true"`
	RemoteDnsDomainStrategy option.DomainStrategy `json:"remote-dns-domain-strategy,omitempty" overridable:"true"`
	DirectDnsAddress        string                `json:"direct-dns-address,omitempty" overridable:"true"`
	DirectDnsDomainStrategy option.DomainStrategy `json:"direct-dns-domain-strategy,omitempty" overridable:"true"`
	IndependentDNSCache     bool                  `json:"independent-dns-cache,omitempty"`
	EnableFakeDNS           bool                  `json:"enable-fake-dns,omitempty"`
	// EnableDNSRouting        bool                  `json:"enable-dns-routing,omitempty"`
}

type InboundOptions struct {
	EnableTun        bool   `json:"enable-tun,omitempty"`
	EnableTunService bool   `json:"enable-tun-service,omitempty"`
	SetSystemProxy   bool   `json:"set-system-proxy,omitempty"`
	MixedPort        uint16 `json:"mixed-port,omitempty"`
	TProxyPort       uint16 `json:"tproxy-port,omitempty"`
	RedirectPort     uint16 `json:"redirect-port,omitempty"`
	DirectPort       uint16 `json:"direct-port,omitempty"`
	MTU              uint32 `json:"mtu,omitempty"`
	StrictRoute      bool   `json:"strict-route,omitempty"`
	TUNStack         string `json:"tun-implementation,omitempty"`
}

type URLTestOptions struct {
	ConnectionTestUrl  string            `json:"connection-test-url,omitempty" overridable:"true"`
	ConnectionTestUrls []string          `json:"connection-test-urls,omitempty" overridable:"true"`
	URLTestInterval    DurationInSeconds `json:"url-test-interval,omitempty" overridable:"true"`
	// URLTestIdleTimeout DurationInSeconds `json:"url-test-idle-timeout"`
}

type RouteOptions struct {
	ResolveDestination     bool                  `json:"resolve-destination,omitempty"`
	IPv6Mode               option.DomainStrategy `json:"ipv6-mode,omitempty"`
	BypassLAN              bool                  `json:"bypass-lan,omitempty"`
	AllowConnectionFromLAN bool                  `json:"allow-connection-from-lan,omitempty"`
	BlockQuic              bool                  `json:"block-quic,omitempty"`
}

type TLSTricks struct {
	EnableFragment bool   `json:"enable-fragment,omitempty" overridable:"true"`
	FragmentSize   string `json:"fragment-size,omitempty" overridable:"true"`
	FragmentSleep  string `json:"fragment-sleep,omitempty" overridable:"true"`
	MixedSNICase   bool   `json:"mixed-sni-case,omitempty" overridable:"true"`
	EnablePadding  bool   `json:"enable-padding,omitempty" overridable:"true"`
	PaddingSize    string `json:"padding-size,omitempty" overridable:"true"`
}

type MuxOptions struct {
	Enable     bool   `json:"enable,omitempty" overridable:"true"`
	Padding    bool   `json:"padding,omitempty" overridable:"true"`
	MaxStreams int    `json:"max-streams,omitempty" overridable:"true"`
	Protocol   string `json:"protocol,omitempty" overridable:"true"`
}

type WarpOptions struct {
	Id                 string              `json:"id,omitempty"`
	EnableWarp         bool                `json:"enable,omitempty"`
	Mode               string              `json:"mode,omitempty"`
	WireguardConfigStr string              `json:"wireguard-config,omitempty"`
	WireguardConfig    WarpWireguardConfig `json:"wireguardConfig,omitempty"` // TODO check
	FakePackets        string              `json:"noise,omitempty"`
	FakePacketSize     string              `json:"noise-size,omitempty"`
	FakePacketDelay    string              `json:"noise-delay,omitempty"`
	FakePacketMode     string              `json:"noise-mode,omitempty"`
	CleanIP            string              `json:"clean-ip,omitempty"`
	CleanPort          uint16              `json:"clean-port,omitempty"`
	Account            WarpAccount
}

func DefaultInhiveOptions() *InhiveOptions {
	return &InhiveOptions{
		EnableNTP: true,
		DNSOptions: DNSOptions{
			RemoteDnsAddress:        "1.1.1.1",
			RemoteDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyAsIS),
			DirectDnsAddress:        "1.1.1.1",
			DirectDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyAsIS),
			IndependentDNSCache:     false,
			EnableFakeDNS:           false,
			// EnableDNSRouting:        false,
		},
		InboundOptions: InboundOptions{
			EnableTun:      false,
			SetSystemProxy: false,
			MixedPort:      12334,
			TProxyPort:     12335,
			RedirectPort:   12336,
			DirectPort:     12337,
			MTU:            9000,
			StrictRoute:    true,
			TUNStack:       "mixed",
		},
		URLTestOptions: URLTestOptions{
			ConnectionTestUrl: "http://cp.cloudflare.com/",
			URLTestInterval:   DurationInSeconds(600),
			// URLTestIdleTimeout: DurationInSeconds(6000),
		},
		RouteOptions: RouteOptions{
			ResolveDestination:     false,
			IPv6Mode:               option.DomainStrategy(C.DomainStrategyAsIS),
			BypassLAN:              false,
			AllowConnectionFromLAN: false,
		},
		LogLevel: "debug",
		// LogFile:        "/dev/null",
		LogFile:        "data/box.log",
		Region:         "other",
		EnableClashApi: true,

		ClashApiPort:   16756,
		ClashApiSecret: "",
		// GeoIPPath:      "geoip.db",
		// GeoSitePath:    "geosite.db",
		Rules: []Rule{},
		Mux: MuxOptions{
			Enable:     false,
			Padding:    true,
			MaxStreams: 8,
			Protocol:   "h2mux",
		},
		TLSTricks: TLSTricks{
			EnableFragment: false,
			FragmentSize:   "10-100",
			FragmentSleep:  "50-200",
			MixedSNICase:   false,
			EnablePadding:  false,
			PaddingSize:    "1200-1500",
		},
		UseXrayCoreWhenPossible: false,
	}
}

// GetOverridableInhiveOptions и весь reflect-стек, который её обслуживал
// (setOverridableFields, convertFlatToNested, parseBool/parseInt/parseUint)
// снесены 2026-09-24: 0 читателей в core/ и app/ (единственный вызывающий —
// снесённый 2026-09-23 CLI override-флаг). Поля InhiveOptions, помеченные
// `overridable:"true"`, теперь просто инертные теги — их читал только этот
// стек.
