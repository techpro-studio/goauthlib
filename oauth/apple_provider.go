package oauth

import (
	"context"
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

func (provider *AppleProvider) ExchangeCode(ctx context.Context, code string) (string, error) {
	clientId := provider.ClientId
	remaining, ok := ctx.Value(SocialProviderRemainingKey).(map[string]interface{})
	if ok {
		id, idOk := remaining["client_id"].(string)
		if idOk {
			clientId = id
		}
	}
	secret, err := apple.GenerateClientSecret(provider.Key, provider.TeamId, clientId, provider.KeyId)
	if err != nil {
		return "", gohttplib.HTTP400(err.Error())
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
		return "", gohttplib.HTTP400(err.Error())
	}
	return resp.IDToken, nil
}

func NewAppleProvider(keyId string, key string, clientId string, teamId string) *AppleProvider {
	return &AppleProvider{KeyId: keyId, Key: key, ClientId: clientId, TeamId: teamId}
}

func (provider *AppleProvider) GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error) {
	id, err := apple.GetUniqueID(token)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	claim, err := apple.GetClaims(token)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	email := (*claim)["email"].(string)
	result := ProviderResult{
		ID:    id,
		Type:  "apple",
		Email: email,
		Phone: "",
		Raw:   map[string]interface{}(*claim),
	}
	return &result, nil
}

func (provider *AppleProvider) GetOAuthConfig() *oauth2.Config {
	return nil
}
