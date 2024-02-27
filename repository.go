package goauthlib

import (
	"context"
	"github.com/techpro-studio/goauthlib/oauth"
)

type Repository interface {
	GetForEntity(ctx context.Context, entity AuthorizationEntity) *User
	CreateForEntity(ctx context.Context, entity AuthorizationEntity) *User
	GetForSocial(ctx context.Context, result *oauth.ProviderResult) *User
	EnsureService(ctx context.Context, id string)
	RemoveService(ctx context.Context, id string)
	CreateForSocial(ctx context.Context, result *oauth.ProviderResult) *User
	Save(ctx context.Context, model *User)
	GetVerificationForEntity(ctx context.Context, entity AuthorizationEntity) *Verification
	GetVerificationForServiceRemoval(ctx context.Context) *Verification
	CreateServiceRemovalVerification(ctx context.Context, verificationCode string)
	CreateVerificationForEntity(ctx context.Context, entity AuthorizationEntity, verificationCode string)
	DeleteVerification(ctx context.Context, id string)
	GetById(ctx context.Context, id string) *User
	SaveOAuthData(ctx context.Context, result *oauth.ProviderResult)
	GetTokensFor(ctx context.Context, entity *AuthorizationEntity) (*oauth.Tokens, error)
}
