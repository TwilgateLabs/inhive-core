package ray2sing

import (
	T "github.com/sagernet/sing-box/option"

	"strings"
)

func SSHSingbox(sshURL string) (*T.Outbound, error) {
	u, err := ParseUrl(sshURL, 22)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	prefix := "-----BEGIN OPENSSH PRIVATE KEY-----"
	suffix := "-----END OPENSSH PRIVATE KEY-----"

	privkeys := strings.Split(decoded["pk"], ",")
	if len(privkeys) == 1 && privkeys[0] == "" {
		privkeys = []string{}
	}
	for i := 0; i < len(privkeys); i++ {
		if !strings.Contains(privkeys[i], prefix) {
			privkeys[i] = prefix + "\n" + privkeys[i]
		}
		if !strings.Contains(privkeys[i], suffix) {
			privkeys[i] = privkeys[i] + "\n" + suffix
		}
		privkeys[i] = strings.ReplaceAll(privkeys[i], prefix, prefix+"\n")
		privkeys[i] = strings.ReplaceAll(privkeys[i], suffix, "\n"+suffix)
	}

	hostkeys := strings.Split(decoded["hk"], ",")
	// strings.Split("", ",") == [""], which sing-box treats as a non-empty list
	// and fails to parse ("parse host key nil"). Nil it out for accept-any.
	if len(hostkeys) == 1 && hostkeys[0] == "" {
		hostkeys = nil
	}

	hostKeyAlgorithms := strings.Split(decoded["hka"], ",")
	if len(hostKeyAlgorithms) == 1 && hostKeyAlgorithms[0] == "" {
		hostKeyAlgorithms = nil
	}

	result := T.Outbound{
		Type: "ssh",
		Tag:  u.Name,
		Options: &T.SSHOutboundOptions{
			ServerOptions:        u.GetServerOption(),
			User:                 u.Username,
			Password:             u.Password,
			PrivateKey:           privkeys,
			PrivateKeyPassphrase: decoded["pk_passphrase"],
			HostKey:              hostkeys,
			HostKeyAlgorithms:    hostKeyAlgorithms,
			ClientVersion:        decoded["client_version"],
			UDPOverTCP: &T.UDPOverTCPOptions{
				Enabled: true,
			},
		},
	}
	return &result, nil
}
