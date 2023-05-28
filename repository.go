package goauthlib

import (
	"context"
	"github.com/techpro-studio/goauthlib/oauth"
)

type Repository interface {
	GetForEntity(ctx context.Context, entity AuthorizationEntity) *User
	CreateForEntity(ctx context.Context, entity AuthorizationEntity) *User
	GetForSocial(ctx context.Context, result *oauth.ProviderResult) *User
	CreateForSocial(ctx context.Context, result *oauth.ProviderResult) *User
	Save(ctx context.Context, model *User)
	GetVerificationForEntity(ctx context.Context, entity AuthorizationEntity) *Verification
	CreateVerification(ctx context.Context, entity AuthorizationEntity, verificationCode string)
	DeleteVerification(ctx context.Context, id string)
	GetById(ctx context.Context, id string) *User
}
