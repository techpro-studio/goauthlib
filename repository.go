package goauthlib

import "github.com/techpro-studio/goauthlib/social"

type Repository interface {
	GetForEntity(entity AuthorizationEntity) *User
	CreateForEntity(entity AuthorizationEntity) *User
	GetForSocial(result *social.ProviderResult) *User
	CreateForSocial(result *social.ProviderResult) *User
	Save(model *User)
	GetVerificationForEntity(entity AuthorizationEntity) *Verification
	CreateVerification(entity AuthorizationEntity, verificationCode string)*Verification
	GetById(id string) *User
}
