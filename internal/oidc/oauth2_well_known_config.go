package oidc

import (
	"encoding/json"
	"fmt"

	"github.com/authelia/authelia/internal/middlewares"
)

type configurationJSON struct {
	Issuer                 string   `json:"issuer"`
	AuthURL                string   `json:"authorization_endpoint"`
	TokenURL               string   `json:"token_endpoint"`
	JWKSURL                string   `json:"jwks_uri"`
	UserInfoURL            string   `json:"userinfo_endpoint"`
	Algorithms             []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

// WellKnownConfigurationGet handler serving the openid configuration.
func WellKnownConfigurationGet(req *middlewares.AutheliaCtx) {
	forwardedOrigin, err := middlewares.GetForwardedOrigin(req)
	if err != nil {
		req.Error(fmt.Errorf("Unable to retrieve forwarded origin: %v", err), "Operation failed")
		return
	}

	forwardedOriginWithBasePath, err := middlewares.GetForwardedOriginWithBasePath(req)
	if err != nil {
		req.Error(fmt.Errorf("Unable to retrieve forwarded origin: %v", err), "Operation failed")
		return
	}

	var configuration configurationJSON

	configuration.Issuer = forwardedOrigin
	configuration.AuthURL = fmt.Sprintf("%s/api/oidc/auth", forwardedOriginWithBasePath)
	configuration.TokenURL = fmt.Sprintf("%s/api/oidc/token", forwardedOriginWithBasePath)
	configuration.JWKSURL = fmt.Sprintf("%s/api/oidc/jwks", forwardedOriginWithBasePath)
	configuration.UserInfoURL = fmt.Sprintf("%s/api/oidc/userinfo", forwardedOriginWithBasePath)
	configuration.Algorithms = []string{"RS256"}
	configuration.ResponseTypesSupported = []string{
		"code",
		"token",
		"id_token",
		"code token",
		"code id_token",
		"token id_token",
		"code token id_token",
		"none",
	}

	if err := json.NewEncoder(req).Encode(configuration); err != nil {
		req.Error(err, "Failed to serve openid configuration")
	}
}
