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
