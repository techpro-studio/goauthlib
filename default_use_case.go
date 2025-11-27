package goauthlib

import (
	"context"
	"errors"
	"fmt"
	"github.com/techpro-studio/goauthlib/oauth"
	"github.com/techpro-studio/gohttplib"
	"math/rand"
)

type OTPDelivery interface {
	SendOTP(ctx context.Context, destination, otp string) error
}

type UserCaseCallback interface {
	OnSignUserWithSocial(ctx context.Context, user *User, provider oauth.ProviderResult)
	OnCreateUser(ctx context.Context, user *User)
	OnUpdateUser(ctx context.Context, user *User)
	OnAddService(ctx context.Context, user *User)
	OnRemoveServiceFrom(ctx context.Context, user *User) error
}

func DoNothingCallback() UserCaseCallback {
	return DoNothingUseCaseCallback{}
}

type DoNothingUseCaseCallback struct {
}

func (d DoNothingUseCaseCallback) OnSignUserWithSocial(ctx context.Context, user *User, provider oauth.ProviderResult) {
}

func (d DoNothingUseCaseCallback) OnCreateUser(ctx context.Context, user *User) {
}

func (d DoNothingUseCaseCallback) OnUpdateUser(ctx context.Context, user *User) {
}

func (d DoNothingUseCaseCallback) OnAddService(ctx context.Context, user *User) {
}

func (d DoNothingUseCaseCallback) OnRemoveServiceFrom(ctx context.Context, user *User) error {
	return nil
}

type DefaultUseCase struct {
	SocialProviders            map[string]oauth.SocialProvider
	Deliveries                 map[string]OTPDelivery
	repository                 Repository
	callback                   UserCaseCallback
	jwtConfig                  JWTConfig
	softDeleteUserIfNoServices bool
}

func (useCase *DefaultUseCase) SetSoftDeleteUserIfNoServices(softDeleteUserIfNoServices bool) {
	useCase.softDeleteUserIfNoServices = softDeleteUserIfNoServices
}

func (useCase *DefaultUseCase) UpsertUser(ctx context.Context, entity AuthorizationEntity, info map[string]any) (*Response, error) {
	user, err := useCase.repository.UpsertForEntity(ctx, entity, info)
	if err != nil {
		return nil, err
	}
	token, err := useCase.jwtConfig.GenerateTokenFromModel(*user)
	if err != nil {
		return nil, err
	}
	return &Response{
		Token:    token,
		User:     *user,
		UserInfo: nil,
	}, nil
}

func (useCase *DefaultUseCase) PatchUserInfo(ctx context.Context, usr *User, body map[string]interface{}) (*User, error) {
	for k, v := range body {
		usr.Info[k] = v
	}
	useCase.repository.Save(ctx, usr)
	return usr, nil
}

func (useCase *DefaultUseCase) RegisterOTPDelivery(key string, delivery OTPDelivery) {
	useCase.Deliveries[key] = delivery
}

func NewDefaultUseCase(repository Repository, config JWTConfig, callback UserCaseCallback) *DefaultUseCase {
	return &DefaultUseCase{repository: repository, SocialProviders: map[string]oauth.SocialProvider{}, Deliveries: map[string]OTPDelivery{}, jwtConfig: config, callback: callback}
}

func (useCase *DefaultUseCase) RegisterSocialProvider(key string, provider oauth.SocialProvider) {
	useCase.SocialProviders[key] = provider
}

func (useCase *DefaultUseCase) AuthenticateViaSocialProvider(ctx context.Context, payload SocialProviderPayload) (*Response, error) {
	result, err := useCase.getInfoFromProvider(ctx, payload)
	if err != nil {
		return nil, err
	}
	usr := useCase.repository.GetForSocial(ctx, result)
	if usr == nil {
		usr = useCase.repository.CreateForSocial(ctx, result)
		useCase.callback.OnCreateUser(ctx, usr)
	} else {
		if useCase.repository.EnsureService(ctx, usr.ID) {
			useCase.callback.OnAddService(ctx, usr)
		}
		useCase.appendNewEntitiesFromSocialToUserIfNeed(ctx, usr, result)
	}
	useCase.callback.OnSignUserWithSocial(ctx, usr, *result)
	useCase.repository.SaveOAuthData(ctx, result)
	return useCase.generateResponseFor(usr, result.Raw)
}

func (useCase *DefaultUseCase) appendNewEntitiesFromSocialToUserIfNeed(ctx context.Context, usr *User, result *oauth.ProviderResult) {
	newEntities := useCase.findNewEntitiesInSocialProviderResult(usr.Entities, result)
	if len(newEntities) > 0 {
		usr.Entities = append(usr.Entities, newEntities...)
		useCase.saveUser(ctx, usr)
	}
}

func (useCase *DefaultUseCase) saveUser(ctx context.Context, user *User) {
	useCase.repository.Save(ctx, user)
	useCase.callback.OnUpdateUser(ctx, user)
}

func (useCase *DefaultUseCase) getInfoFromProvider(ctx context.Context, payload SocialProviderPayload) (*oauth.ProviderResult, error) {
	provider := useCase.SocialProviders[payload.Provider]
	if provider == nil {
		return nil, gohttplib.HTTP400(fmt.Sprintf("%s is not registered", payload.Provider))
	}
	if len(payload.Remaining) > 0 {
		ctx = context.WithValue(ctx, oauth.SocialProviderRemainingKey, payload.Remaining)
	}
	var result oauth.Result
	var infoToken string
	if payload.PayloadType == "code" {
		res, err := provider.ExchangeCode(ctx, payload.Payload)
		if err != nil {
			return nil, gohttplib.HTTP400(err.Error())
		}
		result = *res
		infoToken = result.InfoToken
	} else {
		result = oauth.Result{
			Tokens: oauth.Tokens{
				Access: payload.Payload,
			},
		}
		infoToken = payload.Payload
	}

	providerResult, err := provider.GetInfoByToken(ctx, infoToken)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	providerResult.Tokens = result.Tokens
	return providerResult, nil
}

func (useCase *DefaultUseCase) generateResponseFor(usr *User, userInfo map[string]interface{}) (*Response, error) {
	jsonWebToken, err := useCase.jwtConfig.GenerateTokenFromModel(*usr)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	return &Response{
		Token:    jsonWebToken,
		User:     *usr,
		UserInfo: userInfo,
	}, nil
}

func (useCase *DefaultUseCase) VerifyDelete(ctx context.Context, user User, code string) error {
	verification := useCase.repository.GetServiceActionVerification(ctx, deleteAccountAction)
	if verification.Code != code {
		return gohttplib.HTTP400("code is not equal")
	}
	return useCase.ForceDelete(ctx, user)
}

func (useCase *DefaultUseCase) ForceDelete(ctx context.Context, user User) error {
	useCase.repository.RemoveService(ctx, user.ID, useCase.softDeleteUserIfNoServices, func(ctx context.Context, userId string) error {
		return useCase.callback.OnRemoveServiceFrom(ctx, &user)
	})
	for _, entity := range user.Entities {
		provider := useCase.SocialProviders[entity.Type]
		if provider != nil {
			tokens, _ := useCase.repository.GetTokensFor(ctx, &entity)
			if tokens != nil {
				_ = provider.RevokeTokens(ctx, *tokens)
			}
		}
	}

	return nil
}

func (useCase *DefaultUseCase) SendVerificationCode(ctx context.Context, user User, action string) error {
	errs := []error{}
	code := fmt.Sprintf("%d", rand.Intn(899999)+100000)
	delivery := useCase.Deliveries[EntityTypeEmail]
	useCase.repository.CreateServiceActionVerification(ctx, action, code)
	for _, entity := range user.Entities {
		if entity.Type == EntityTypeEmail {
			err := delivery.SendOTP(ctx, entity.Value, code)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (useCase *DefaultUseCase) SendCode(ctx context.Context, entity AuthorizationEntity) error {
	code := fmt.Sprintf("%d", rand.Intn(899999)+100000)
	dataDelivery := useCase.Deliveries[entity.Type]
	if dataDelivery == nil {
		return gohttplib.HTTP400("type not found")
	}
	useCase.repository.CreateVerificationForEntity(ctx, entity, code)
	err := dataDelivery.SendOTP(ctx, entity.Value, code)
	return err
}

func (useCase *DefaultUseCase) SendCodeWithUser(ctx context.Context, user User, entity AuthorizationEntity) error {
	usrAttached := useCase.repository.GetForEntity(ctx, entity)
	if usrAttached != nil {
		if usrAttached.ID != user.ID {
			return entityHasAlreadyUser
		}
	}
	return useCase.SendCode(ctx, entity)
}

func (useCase *DefaultUseCase) AuthenticateWithCode(ctx context.Context, entity AuthorizationEntity, code string) (*Response, error) {
	verification, err := useCase.getVerificationAndCompare(ctx, entity, code)
	if err != nil {
		return nil, err
	}
	usr := useCase.repository.GetForEntity(ctx, entity)
	if usr == nil {
		usr = useCase.repository.CreateForEntity(ctx, entity)
		useCase.callback.OnCreateUser(ctx, usr)
	} else {
		useCase.repository.EnsureService(ctx, usr.ID)
	}
	useCase.repository.DeleteVerification(ctx, verification.ID)
	return useCase.generateResponseFor(usr, usr.Info)
}

func (useCase *DefaultUseCase) getVerificationAndCompare(ctx context.Context, entity AuthorizationEntity, code string) (*Verification, error) {
	verification := useCase.repository.GetVerificationForEntity(ctx, entity)
	if verification == nil {
		return nil, gohttplib.HTTP404(entity.Value)
	}
	if verification.Code != code {
		return nil, invalidCode
	}
	return verification, nil
}

func (useCase *DefaultUseCase) foundEntityInUser(user User, entity AuthorizationEntity) int {
	foundIdx := -1
	for idx, e := range user.Entities {
		if e.isEqual(entity) {
			foundIdx = idx
		}
	}
	return foundIdx
}

func (useCase *DefaultUseCase) RemoveAuthenticationEntity(ctx context.Context, user User, entity AuthorizationEntity) error {
	foundIdx := useCase.foundEntityInUser(user, entity)
	if foundIdx == -1 {
		return gohttplib.HTTP404(entity.Value)
	}
	if len(user.Entities) == 1 {
		return cantDeleteLastEntity
	}
	usrEntities := user.Entities
	usrEntities = append(usrEntities[:foundIdx], usrEntities[foundIdx+1:]...)
	user.Entities = usrEntities
	useCase.repository.Save(ctx, &user)
	return nil
}

func (useCase *DefaultUseCase) AddSocialAuthenticationEntity(ctx context.Context, user *User, payload SocialProviderPayload) (*User, error) {
	result, err := useCase.getInfoFromProvider(ctx, payload)
	if err != nil {
		return nil, err
	}
	usrAttached := useCase.repository.GetForSocial(ctx, result)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return nil, entityAlreadyExists
		} else {
			return nil, entityHasAlreadyUser
		}
	}
	useCase.appendNewEntitiesFromSocialToUserIfNeed(ctx, user, result)
	useCase.repository.SaveOAuthData(ctx, result)
	return user, nil
}

func (useCase *DefaultUseCase) VerifyAuthenticationEntity(ctx context.Context, user *User, entity AuthorizationEntity, code string) (*User, error) {
	usrAttached := useCase.repository.GetForEntity(ctx, entity)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return nil, entityAlreadyExists
		} else {
			return nil, entityHasAlreadyUser
		}
	}
	verification, err := useCase.getVerificationAndCompare(ctx, entity, code)
	if err != nil {
		return nil, err
	}
	usrEntities := user.Entities
	usrEntities = append(usrEntities, entity)
	user.Entities = usrEntities
	useCase.saveUser(ctx, user)
	useCase.repository.DeleteVerification(ctx, verification.ID)
	return user, nil
}

func (useCase *DefaultUseCase) findNewEntitiesInSocialProviderResult(old []AuthorizationEntity, result *oauth.ProviderResult) []AuthorizationEntity {
	socialEntity := AuthorizationEntity{Type: result.Type, Value: result.ID}
	socialMap := map[string]*AuthorizationEntity{
		socialEntity.GetHash(): &socialEntity,
	}
	if result.Email != "" {
		emailEntity := AuthorizationEntity{
			Value: result.Email,
			Type:  EntityTypeEmail,
		}
		socialMap[emailEntity.GetHash()] = &emailEntity
	}
	if result.Phone != "" {
		emailEntity := AuthorizationEntity{
			Value: result.Email,
			Type:  EntityTypeEmail,
		}
		socialMap[emailEntity.GetHash()] = &emailEntity
	}
	var newEntities []AuthorizationEntity

	for _, oldEntity := range old {
		if socialMap[oldEntity.GetHash()] != nil {
			delete(socialMap, oldEntity.GetHash())
		}
	}

	for _, value := range socialMap {
		newEntities = append(newEntities, *value)
	}
	return newEntities
}

func (useCase *DefaultUseCase) ExtractAvatarUrlFromSocialProvider(ctx context.Context, userId string) *string {
	user := useCase.repository.GetById(ctx, userId)
	if user == nil {
		return nil
	}

	for _, entity := range user.Entities {
		provider, ok := useCase.SocialProviders[entity.Type]
		if !ok {
			continue
		}
		url, err := provider.ExtractAvatarUrl(ctx, entity.Value)
		if err != nil {
			continue
		}
		if url == nil {
			continue
		}
		return url
	}
	return nil
}
