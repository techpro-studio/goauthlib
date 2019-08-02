package goauthlib

type Repository interface {
	GetForEntity(entity AuthorizationEntity) *User
	CreateForEntity(entity AuthorizationEntity) *User
	GetForSocial(result *ProviderResult) *User
	CreateForSocial(result *ProviderResult) *User
	Save(model *User)
	GetVerificationForEntity(entity AuthorizationEntity) *Verification
	CreateVerification(entity AuthorizationEntity, verificationCode string)
	DeleteVerification(id string)
	GetById(id string) *User
}
