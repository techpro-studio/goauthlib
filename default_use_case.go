package goauthlib

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/techpro-studio/goauthlib/oauth"
	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/gohttplib/utils"
	"math/rand"
)

type Config struct {
	sharedSecret string
}

func NewConfig(sharedSecret string) *Config {
	return &Config{sharedSecret: sharedSecret}
}

type OTPDelivery interface {
	SendOTP(ctx context.Context, destination, otp string) error
}

type DefaultUseCase struct {
	SocialProviders map[string]oauth.SocialProvider
	Deliveries      map[string]OTPDelivery
	repository      Repository
	config          Config
}

func (useCase *DefaultUseCase) RegisterOTPDelivery(key string, delivery OTPDelivery) {
	useCase.Deliveries[key] = delivery
}

func NewDefaultUseCase(repository Repository, config Config) *DefaultUseCase {
	return &DefaultUseCase{repository: repository, SocialProviders: map[string]oauth.SocialProvider{}, Deliveries: map[string]OTPDelivery{}, config: config}
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
	} else {
		useCase.appendNewEntitiesFromSocialToUserIfNeed(ctx, usr, result)
	}
	useCase.repository.SaveOAuthData(ctx, result)
	return useCase.generateResponseFor(usr, result.Raw)
}

func (useCase *DefaultUseCase) appendNewEntitiesFromSocialToUserIfNeed(ctx context.Context, usr *User, result *oauth.ProviderResult) {
	newEntities := useCase.findNewEntitiesInSocialProviderResult(usr.Entities, result)
	if len(newEntities) > 0 {
		usr.Entities = append(usr.Entities, newEntities...)
		useCase.repository.Save(ctx, usr)
	}
}

func (useCase *DefaultUseCase) getInfoFromProvider(ctx context.Context, payload SocialProviderPayload) (*oauth.ProviderResult, error) {
	provider := useCase.SocialProviders[payload.Provider]
	if provider == nil {
		return nil, gohttplib.HTTP400(fmt.Sprintf("%s is not registered", payload.Provider))
	}
	if len(payload.Remaining) > 0 {
		ctx = context.WithValue(ctx, oauth.SocialProviderRemainingKey, payload.Remaining)
	}
	var token string
	if payload.PayloadType == "token" {
		token = payload.Payload
	} else {
		result, err := provider.ExchangeCode(ctx, payload.Payload)
		if err != nil {
			return nil, gohttplib.HTTP400(err.Error())
		}
		token = result
	}
	result, err := provider.GetInfoByToken(ctx, token)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	return result, nil
}

func (useCase *DefaultUseCase) generateResponseFor(usr *User, userInfo map[string]interface{}) (*Response, error) {
	jsonWebToken, err := useCase.generateTokenFromModel(*usr)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	return &Response{
		Token:    jsonWebToken,
		User:     *usr,
		UserInfo: userInfo,
	}, nil
}

func (useCase *DefaultUseCase) SendCode(ctx context.Context, entity AuthorizationEntity) error {
	code := fmt.Sprintf("%d", rand.Intn(8999999)+1000000)
	dataDelivery := useCase.Deliveries[entity.Type]
	if dataDelivery == nil {
		return gohttplib.HTTP400("type not found")
	}
	useCase.repository.CreateVerification(ctx, entity, code)
	err := dataDelivery.SendOTP(ctx, entity.Value, code)
	return err
}

func (useCase *DefaultUseCase) SendCodeWithUser(ctx context.Context, user User, entity AuthorizationEntity) error {
	usrAttached := useCase.repository.GetForEntity(ctx, entity)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return entityAlreadyExists
		} else {
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
	}
	useCase.repository.DeleteVerification(ctx, verification.ID)
	return useCase.generateResponseFor(usr, nil)
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
	useCase.repository.Save(ctx, user)
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

func (useCase *DefaultUseCase) GetValidModelFromToken(ctx context.Context, token string) *User {
	userData, err := useCase.getUserDataFromToken(token)
	if err != nil {
		return nil
	}
	model := useCase.repository.GetById(ctx, userData["id"].(string))
	if model == nil {
		return nil
	}
	if useCase.generateTokenHash(*model) != userData["hash"] {
		return nil
	}
	return model
}

func (useCase *DefaultUseCase) getUserDataFromToken(token string) (map[string]interface{}, error) {

	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(useCase.config.sharedSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if ok && tokenObj.Valid {
		return claims, nil
	}
	return nil, errors.New("Failed jwt")
}

func (useCase *DefaultUseCase) generateTokenHash(model User) string {
	return useCase.config.sharedSecret + utils.GetMD5Hash(model.ID)
}

func (useCase *DefaultUseCase) generateTokenFromModel(model User) (string, error) {
	hash := useCase.generateTokenHash(model)
	claims := struct {
		ID   string `json:"id"`
		Hash string `json:"hash"`
		jwt.StandardClaims
	}{
		model.ID,
		hash,
		jwt.StandardClaims{
			Issuer: "auth",
		},
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tokenObj.SignedString([]byte(useCase.config.sharedSecret))
	if err != nil {
		return "", err
	}
	return token, nil
}
