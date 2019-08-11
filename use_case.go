package goauthlib

import "github.com/techpro-studio/godelivery"

//UseCase is an abstraction over auth business logic
type UseCase interface {
	RegisterSocialProvider(key string, provider Provider)
	RegisterDataDelivery(key string, delivery delivery.DataDelivery)
	AuthenticateViaSocialProvider(providerType string, token string) (*Response, error)
	SendCode(entity AuthorizationEntity) error
	GetValidModelFromToken(token string)*User
	AuthenticateWithCode(entity AuthorizationEntity, code string)(*Response, error)
	RemoveAuthenticationEntity(user User, entity AuthorizationEntity) error
	SendCodeWithUser(user User, entity AuthorizationEntity) error
	AddSocialAuthenticationEntity(user *User, socialProvider string, token string) (*User,error)
	VerifyAuthenticationEntity(user *User, entity AuthorizationEntity, code string) (*User,error)
}
