// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/x/httpx"
)

type ProviderRSO struct {
	*ProviderGenericOIDC
}

var (
	rsoAuthEndpoint = oauth2.Endpoint{
		AuthURL:   "https://auth.riotgames.com/authorize",
		TokenURL:  "https://auth.riotgames.com/token",
		AuthStyle: oauth2.AuthStyleInHeader,
	}
	rsoUserEndpoint = "https://auth.riotgames.com/userinfo"
)

func NewProviderRSO(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderRSO{
		&ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

func (rs *ProviderRSO) Config() *Configuration {
	return rs.config
}

func (rs *ProviderRSO) OAuth2(ctx context.Context) (*oauth2.Config, error) {

	return &oauth2.Config{
		ClientID:     rs.config.ClientID,
		ClientSecret: rs.config.ClientSecret,
		Endpoint:     rsoAuthEndpoint,
		// rso uses fixed scope that can not be configured in runtime
		Scopes:      rs.config.Scope,
		RedirectURL: rs.config.Redir(rs.reg.Config().OIDCRedirectURIBase(ctx)),
	}, nil

}

func (rs *ProviderRSO) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	// rsoClaim is defined in the https://open.feishu.cn/document/common-capabilities/sso/api/get-user-info
	type rsoClaim struct {
		SubSid string `json:"sub_sid"`
	}
	var (
		client = rs.reg.HTTPClient(ctx, httpx.ResilientClientDisallowInternalIPs())
		user   rsoClaim
	)

	req, err := retryablehttp.NewRequest("GET", rsoUserEndpoint, nil)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	exchange.SetAuthHeader(req.Request)
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer res.Body.Close()

	if err := logUpstreamError(rs.reg.Logger(), res); err != nil {
		return nil, err
	}

	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	return &Claims{
		Issuer:  rsoUserEndpoint,
		Subject: user.SubSid,
	}, nil
}

func (rs *ProviderRSO) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{}
}
