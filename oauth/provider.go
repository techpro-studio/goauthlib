package oauth

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
)

const (
	EntityTypeOAuthFacebook = "facebook"
	EntityTypeOAuthApple    = "apple"
	EntityTypeOAuthGithub   = "github"
	EntityTypeOAuthGoogle   = "google"
)

// ProviderResult is a result of authentication via social provider
type ProviderResult struct {
	ID     string
	Type   string
	Email  string
	Phone  string
	Tokens Tokens
	Raw    map[string]interface{}
}

const SocialProviderRemainingKey = "oauth_remaining"

type Tokens struct {
	Access  string `json:"access" bson:"access"`
	Refresh string `json:"refresh" bson:"refresh"`
}

type Result struct {
	Tokens
	InfoToken string
}

// SocialProvider is a fetcher through the social providers
type SocialProvider interface {
	GetInfoByToken(ctx context.Context, infoToken string) (*ProviderResult, error)
	ExchangeCode(ctx context.Context, code string) (*Result, error)
	RevokeTokens(ctx context.Context, tokens Tokens) error
	ExtractAvatarUrl(ctx context.Context, id string) (*string, error)
}

func ExchangeCodeUsingProvider(config *oauth2.Config, ctx context.Context, code string) (*Result, error) {
	if config == nil {
		return nil, errors.New("your app configured for token based authentication only")
	}
	exchange, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return &Result{
		Tokens: Tokens{
			Access:  exchange.AccessToken,
			Refresh: exchange.RefreshToken,
		},
		InfoToken: exchange.AccessToken,
	}, nil
}
