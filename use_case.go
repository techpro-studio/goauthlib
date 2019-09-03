package goauthlib

import (
	"context"
	"github.com/techpro-studio/godelivery"
)

//UseCase is an abstraction over auth business logic
type UseCase interface {
	RegisterSocialProvider(key string, provider Provider)
	RegisterDataDelivery(key string, delivery delivery.DataDelivery)
	AuthenticateViaSocialProvider(ctx context.Context, providerType string, token string) (*Response, error)
	SendCode(ctx context.Context, entity AuthorizationEntity) error
	GetValidModelFromToken(ctx context.Context, token string)*User
	AuthenticateWithCode(ctx context.Context, entity AuthorizationEntity, code string)(*Response, error)
	RemoveAuthenticationEntity(ctx context.Context, user User, entity AuthorizationEntity) error
	SendCodeWithUser(ctx context.Context,user User, entity AuthorizationEntity) error
	AddSocialAuthenticationEntity(ctx context.Context, user *User, socialProvider string, token string) (*User,error)
	VerifyAuthenticationEntity(ctx context.Context,user *User, entity AuthorizationEntity, code string) (*User,error)
}
