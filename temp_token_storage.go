package goauthlib

import "context"

type TempTokenStorage interface {
	SetTempTokenForUser(ctx context.Context, token string, userId string, duration int64) error
	GetUserIdForToken(ctx context.Context, token string) (string, error)
}

type TempTokenJWTSecretProvider interface {
	GetTempTokenJWTSecret() string
}

type StaticTempTokenJWTSecretProvider struct {
	tempTokenJWTSecret string
}

func NewStaticTempTokenJWTSecretProvider(tempTokenJWTSecret string) *StaticTempTokenJWTSecretProvider {
	return &StaticTempTokenJWTSecretProvider{tempTokenJWTSecret: tempTokenJWTSecret}
}

func (s StaticTempTokenJWTSecretProvider) GetTempTokenJWTSecret() string {
	return s.tempTokenJWTSecret
}
