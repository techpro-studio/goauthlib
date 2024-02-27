package oauth

import (
	"context"
	"errors"
	"github.com/Timothylock/go-signin-with-apple/apple"
	"github.com/techpro-studio/gohttplib"
	"golang.org/x/oauth2"
)

type AppleProvider struct {
	KeyId    string
	Key      string
	ClientId string
	TeamId   string
}

func (provider *AppleProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	secret, err := apple.GenerateClientSecret(provider.Key, provider.TeamId, provider.ClientId, provider.KeyId)
	if err != nil {
		return gohttplib.HTTP400(err.Error())
	}
	client := apple.New()
	var result any

	refreshTokenRequest := apple.RevokeRefreshTokenRequest{
		ClientID:     provider.ClientId,
		ClientSecret: secret,
		RefreshToken: tokens.Refresh,
	}
	refreshErr := client.RevokeRefreshToken(ctx, refreshTokenRequest, &result)

	accessTokenRequest := apple.RevokeAccessTokenRequest{
		AccessToken:  tokens.Access,
		ClientID:     provider.ClientId,
		ClientSecret: secret,
	}
	accessErr := client.RevokeAccessToken(ctx, accessTokenRequest, &result)

	return errors.Join(accessErr, refreshErr)
}

func (provider *AppleProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	clientId := provider.ClientId
	secret, err := apple.GenerateClientSecret(provider.Key, provider.TeamId, clientId, provider.KeyId)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	client := apple.New()

	vReq := apple.AppValidationTokenRequest{
		ClientID:     clientId,
		ClientSecret: secret,
		Code:         code,
	}
	var resp apple.ValidationResponse

	// Do the verification

	err = client.VerifyAppToken(ctx, vReq, &resp)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	return &Result{
		Tokens: Tokens{
			Access:  resp.AccessToken,
			Refresh: resp.RefreshToken,
		},
		InfoToken: resp.IDToken,
	}, nil
}

func NewAppleProvider(keyId string, key string, clientId string, teamId string) *AppleProvider {
	return &AppleProvider{KeyId: keyId, Key: key, ClientId: clientId, TeamId: teamId}
}

func (provider *AppleProvider) GetInfoByToken(ctx context.Context, infoToken string) (*ProviderResult, error) {
	id, err := apple.GetUniqueID(infoToken)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	claim, err := apple.GetClaims(infoToken)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	email := (*claim)["email"].(string)
	result := ProviderResult{
		ID:    id,
		Type:  EntityTypeOAuthApple,
		Email: email,
		Phone: "",
		Raw:   map[string]interface{}(*claim),
	}
	return &result, nil
}

func (provider *AppleProvider) GetOAuthConfig() *oauth2.Config {
	return nil
}
