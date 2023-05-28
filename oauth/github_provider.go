package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
)

type GithubProvider struct {
	config *oauth2.Config
}

func (g GithubProvider) ExchangeCode(ctx context.Context, code string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func NewGithubProvider(config *oauth2.Config) *GithubProvider {
	return &GithubProvider{config: config}
}

func (g GithubProvider) GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error) {
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
		ID:    user["id"].(string),
		Type:  EntityTypeOAuthGithub,
		Email: email,
		Phone: "",
		Raw:   user,
	}, nil
}
