package oauth

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
)

const (
	EntityTypeOAuthFacebook = "facebook"
	EntityTypeOAuthGithub   = "github"
)

// ProviderResult is a result of authentication via social provider
type ProviderResult struct {
	ID    string
	Type  string
	Email string
	Phone string
	Raw   map[string]interface{}
}

const SocialProviderRemainingKey = "oauth_remaining"

// SocialProvider is an fetcher through the social providers
type SocialProvider interface {
	GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error)
	ExchangeCode(ctx context.Context, code string) (string, error)
}

func ExchangeCodeUsingProvider(config *oauth2.Config, ctx context.Context, code string) (string, error) {
	if config == nil {
		return "", errors.New("your app configured for token based authentication only")
	}
	exchange, err := config.Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	return exchange.AccessToken, nil
}
