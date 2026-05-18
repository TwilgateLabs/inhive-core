// warp.go — WARP config generation handler.
// Wires gRPC handler to real config.GenerateWarpInfo (bepass-org/warp-plus).
package hcore

import (
	"context"

	"github.com/twilgate/inhive-core/v2/config"
)

func (s *CoreService) GenerateWarpConfig(ctx context.Context, in *GenerateWarpConfigRequest) (resp *WarpGenerationResponse, err error) {
	return GenerateWarpConfig(in)
}

// GenerateWarpConfig calls the real WARP identity creation in config package
// and maps the result to proto-generated hcore types.
func GenerateWarpConfig(in *GenerateWarpConfigRequest) (*WarpGenerationResponse, error) {
	identity, log, wgConfig, err := config.GenerateWarpInfo(
		in.GetLicenseKey(),
		in.GetAccountId(),
		in.GetAccessToken(),
	)
	if err != nil {
		return &WarpGenerationResponse{
			Config:  &WarpWireguardConfig{},
			Account: &WarpAccount{},
			Log:     "Error: " + err.Error(),
		}, err
	}
	if identity == nil || wgConfig == nil {
		return &WarpGenerationResponse{
			Config:  &WarpWireguardConfig{},
			Account: &WarpAccount{},
			Log:     "Error: empty identity or wgConfig from warp-plus",
		}, nil
	}

	return &WarpGenerationResponse{
		Account: &WarpAccount{
			AccountId:   identity.ID,
			AccessToken: identity.Token,
		},
		Config: &WarpWireguardConfig{
			PrivateKey:       wgConfig.PrivateKey,
			LocalAddressIpv4: wgConfig.LocalAddressIPv4,
			LocalAddressIpv6: wgConfig.LocalAddressIPv6,
			PeerPublicKey:    wgConfig.PeerPublicKey,
			ClientId:         wgConfig.ClientID,
		},
		Log: log,
	}, nil
}
