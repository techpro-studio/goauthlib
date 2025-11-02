package oauth

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
)

type GoogleProvider struct {
	oauthConfig *oauth2.Config
}

func (provider *GoogleProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	return nil
}

func (provider *GoogleProvider) GetOAuthConfig() *oauth2.Config {
	return provider.oauthConfig
}

func NewGoogleProvider(config *oauth2.Config) *GoogleProvider {
	return &GoogleProvider{oauthConfig: config}
}

func (provider *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	return ExchangeCodeUsingProvider(provider.oauthConfig, ctx, code)
}

func (provider *GoogleProvider) ExtractAvatarUrl(ctx context.Context, id string) (*string, error) {
	return nil, nil
}

func (provider *GoogleProvider) GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo?access_token="+token, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user map[string]interface{}

	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}

	email := ""
	if emailParsed, ok := user["email"].(string); ok {
		email = emailParsed
	}

	return &ProviderResult{
		ID:    email,
		Type:  EntityTypeOAuthGoogle,
		Email: email,
		Phone: "",
		Raw:   user,
	}, nil
}
