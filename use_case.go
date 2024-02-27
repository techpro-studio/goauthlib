package goauthlib

import (
	"context"
	"github.com/techpro-studio/goauthlib/oauth"
)

// UseCase is an abstraction over auth business logic
type UseCase interface {
	RegisterSocialProvider(key string, provider oauth.SocialProvider)
	RegisterOTPDelivery(key string, delivery OTPDelivery)
	AuthenticateViaSocialProvider(ctx context.Context, payload SocialProviderPayload) (*Response, error)
	SendCode(ctx context.Context, entity AuthorizationEntity) error
	SendDeleteCode(ctx context.Context, user User) error
	VerifyDelete(ctx context.Context, user User, code string) error
	GetValidModelFromToken(ctx context.Context, token string) *User
	AuthenticateWithCode(ctx context.Context, entity AuthorizationEntity, code string) (*Response, error)
	RemoveAuthenticationEntity(ctx context.Context, user User, entity AuthorizationEntity) error
	SendCodeWithUser(ctx context.Context, user User, entity AuthorizationEntity) error
	AddSocialAuthenticationEntity(ctx context.Context, user *User, payload SocialProviderPayload) (*User, error)
	VerifyAuthenticationEntity(ctx context.Context, user *User, entity AuthorizationEntity, code string) (*User, error)
	PatchUserInfo(ctx context.Context, usr *User, body map[string]interface{}) (*User, error)
}
