package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

type GithubProvider struct {
	oauthConfig *oauth2.Config
}

func (provider *GithubProvider) GetOAuthConfig() *oauth2.Config {
	return provider.oauthConfig
}

func NewGithubProvider(config *oauth2.Config) *GithubProvider {
	return &GithubProvider{oauthConfig: config}
}

func (provider *GithubProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	return ExchangeCodeUsingProvider(provider.oauthConfig, ctx, code)
}

func (provider *GithubProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	return nil
}

func (provider *GithubProvider) GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

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
		ID:    strconv.FormatFloat(user["id"].(float64), 'f', -1, 64),
		Type:  EntityTypeOAuthGithub,
		Email: email,
		Phone: "",
		Raw:   user,
	}, nil
}
