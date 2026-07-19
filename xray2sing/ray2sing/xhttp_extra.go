package ray2sing

import (
	"encoding/json"

	"github.com/sagernet/sing-box/option"
)

type XHTTPExtra struct {
	option.V2RayXHTTPBaseOptions
	DownloadSettings *DownloadSettings `json:"downloadSettings,omitempty"`
}

// UnmarshalJSON parses the XHTTP `extra` object. The obfs fields (uplinkHTTPMethod,
// seqKey/seqPlacement, sessionIDKey/sessionIDPlacement, xPadding*) auto-flow from the
// embedded V2RayXHTTPBaseOptions. After unmarshalling we fold the sessionKey /
// sessionPlacement JSON aliases (used by the trigger config and other Happ exports) into
// the canonical SessionID* fields. Unknown / server-only keys are ignored by default.
//
// A type alias breaks the method set so the standard decoder is used (no recursion); the
// embedded base options have no UnmarshalJSON, so DownloadSettings is preserved.
func (x *XHTTPExtra) UnmarshalJSON(data []byte) error {
	type plain XHTTPExtra
	if err := json.Unmarshal(data, (*plain)(x)); err != nil {
		return err
	}
	x.V2RayXHTTPBaseOptions.NormalizeXHTTPObfsAliases()
	if x.DownloadSettings != nil {
		x.DownloadSettings.V2RayXHTTPBaseOptions.NormalizeXHTTPObfsAliases()
		x.DownloadSettings.normalizeSingboxDialect()
	}
	return nil
}

type DownloadSettings struct {
	option.V2RayXHTTPBaseOptions
	Address         string         `json:"address,omitempty"`
	Port            int            `json:"port,omitempty"`
	Security        string         `json:"security,omitempty"`
	TLSSettings     *TLSConfig     `json:"tlsSettings"`
	REALITYSettings *REALITYConfig `json:"realitySettings"`

	// --- sing-box dialect of the same block. -------------------------------
	// The fields above are Xray's spelling (address/port/security/tlsSettings).
	// A NATIVE sing-box outbound spells the identical concept
	// server/server_port/tls{} — and the app stores parsed nodes as sing-box
	// outbounds and re-parses them on every ping/connect, so this dialect is on
	// the hot path, not an exotic import case. Without these the download leg of
	// an xhttp split node came back with an EMPTY server after one round-trip:
	// the outbound still built (err == nil) but downlink dialing was broken.
	SBServer     string        `json:"server,omitempty"`
	SBServerPort int           `json:"server_port,omitempty"`
	SBTLS        *singboxDLTLS `json:"tls,omitempty"`
}

// singboxDLTLS is the sing-box `tls` block as it appears inside downloadSettings.
type singboxDLTLS struct {
	Enabled    bool         `json:"enabled"`
	ServerName string       `json:"server_name"`
	Insecure   bool         `json:"insecure"`
	ALPN       stringOrList `json:"alpn"`
	UTLS       *struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
}

// normalizeSingboxDialect folds the sing-box spellings onto the Xray fields so
// everything downstream (common.go's Download builder) reads one shape. Xray
// fields win when both are present — an explicit Xray block is never overwritten.
func (d *DownloadSettings) normalizeSingboxDialect() {
	if d.Address == "" && d.SBServer != "" {
		d.Address = d.SBServer
	}
	if d.Port == 0 && d.SBServerPort != 0 {
		d.Port = d.SBServerPort
	}
	if d.SBTLS == nil || !d.SBTLS.Enabled || d.Security != "" {
		return
	}
	if r := d.SBTLS.Reality; r != nil && r.Enabled {
		d.Security = "reality"
		if d.REALITYSettings == nil {
			d.REALITYSettings = &REALITYConfig{
				ServerName: d.SBTLS.ServerName,
				PublicKey:  r.PublicKey,
				ShortId:    r.ShortID,
			}
			if d.SBTLS.UTLS != nil {
				d.REALITYSettings.Fingerprint = d.SBTLS.UTLS.Fingerprint
			}
		}
		return
	}
	d.Security = "tls"
	if d.TLSSettings == nil {
		d.TLSSettings = &TLSConfig{
			ServerName: d.SBTLS.ServerName,
			Insecure:   d.SBTLS.Insecure,
			ALPN:       d.SBTLS.ALPN,
		}
		if d.SBTLS.UTLS != nil {
			d.TLSSettings.Fingerprint = d.SBTLS.UTLS.Fingerprint
		}
	}
}

type TLSConfig struct {
	Insecure bool `json:"allowInsecure"`
	// Certs                   []*TLSCertConfig `json:"certificates"`
	ServerName string   `json:"serverName"`
	ALPN       []string `json:"alpn"`
	// EnableSessionResumption bool     `json:"enableSessionResumption"`
	// DisableSystemRoot       bool             `json:"disableSystemRoot"`
	// MinVersion string `json:"minVersion"`
	// MaxVersion string `json:"maxVersion"`
	// CipherSuites            string           `json:"cipherSuites"`
	Fingerprint      string `json:"fingerprint"`
	RejectUnknownSNI bool   `json:"rejectUnknownSni"`
	// PinnedPeerCertSha256    string           `json:"pinnedPeerCertSha256"`
	// CurvePreferences        *StringList      `json:"curvePreferences"`
	// MasterKeyLog            string           `json:"masterKeyLog"`
	// ServerNameToVerify      string           `json:"serverNameToVerify"`
	// VerifyPeerCertInNames   []string         `json:"verifyPeerCertInNames"`
	// ECHServerKeys           string           `json:"echServerKeys"`
	// ECHConfigList           string           `json:"echConfigList"`
	// ECHForceQuery           string           `json:"echForceQuery"`
	// ECHSocketSettings       *SocketConfig    `json:"echSockopt"`
}

type REALITYConfig struct {
	// MasterKeyLog string          `json:"masterKeyLog"`
	// Show         bool            `json:"show"`
	// Target       json.RawMessage `json:"target"`
	// Dest         json.RawMessage `json:"dest"`
	// Type         string   `json:"type"`
	// Xver         uint64   `json:"xver"`
	// ServerNames  []string `json:"serverNames"`
	// PrivateKey   string   `json:"privateKey"`
	// MinClientVer string   `json:"minClientVer"`
	// MaxClientVer string   `json:"maxClientVer"`
	// MaxTimeDiff  uint64   `json:"maxTimeDiff"`
	// ShortIds     []string `json:"shortIds"`
	// Mldsa65Seed  string   `json:"mldsa65Seed"`

	// LimitFallbackUpload   LimitFallback `json:"limitFallbackUpload"`
	// LimitFallbackDownload LimitFallback `json:"limitFallbackDownload"`

	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	// Password      string `json:"password"`
	PublicKey string `json:"publicKey"`
	ShortId   string `json:"shortId"`
	// Mldsa65Verify string `json:"mldsa65Verify"`
	// SpiderX       string `json:"spiderX"`
}
