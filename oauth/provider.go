package oauth

import "context"

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

// SocialProvider is an fetcher through the social providers
type SocialProvider interface {
	GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error)
	ExchangeCode(ctx context.Context, code string) (string, error)
}
