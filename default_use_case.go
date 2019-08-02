package goauthlib

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/techpro-studio/goauthlib/delivery"
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

type DefaultUseCase struct {
	SocialProviders map[string]Provider
	Deliveries      map[string]delivery.DataDelivery
	repository      Repository
	config          Config
}

func (useCase *DefaultUseCase) RegisterDataDelivery(key string, delivery delivery.DataDelivery) {
	useCase.Deliveries[key] = delivery
}

func NewDefaultUseCase(repository Repository, config Config) *DefaultUseCase {
	return &DefaultUseCase{repository: repository, SocialProviders: map[string]Provider{}, Deliveries: map[string]delivery.DataDelivery{}, config: config}
}

func (useCase *DefaultUseCase) RegisterSocialProvider(key string, provider Provider) {
	useCase.SocialProviders[key] = provider
}

func (useCase *DefaultUseCase) AuthenticateViaSocialProvider(token, _type string) (*Response, error) {
	result, err := useCase.getInfoFromProvider(_type, token)
	if err != nil {
		return nil, err
	}
	usr := useCase.repository.GetForSocial(result)
	if usr == nil {
		usr = useCase.repository.CreateForSocial(result)
	} else {
		useCase.appendNewEntitiesFromSocialToUserIfNeed(usr, result)
	}
	return useCase.generateResponseFor(usr, result.Raw)
}

func (useCase *DefaultUseCase) appendNewEntitiesFromSocialToUserIfNeed(usr *User, result *ProviderResult) {
	newEntities := useCase.findNewEntitiesInSocialProviderResult(usr.Entities, result)
	if len(newEntities) > 0 {
		usr.Entities = append(usr.Entities, newEntities...)
		useCase.repository.Save(usr)
	}
}

func (useCase *DefaultUseCase) getInfoFromProvider(_type string, token string) (*ProviderResult, error) {
	provider := useCase.SocialProviders[_type]
	if provider == nil {
		return nil, gohttplib.HTTP400(fmt.Sprintf("%s is not registered", _type))
	}
	result, err := provider.GetInfoByToken(token)
	if err != nil {
		return nil, err
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

func (useCase *DefaultUseCase) SendCode(entity AuthorizationEntity) error {
	code := fmt.Sprintf("%d", rand.Intn(89999)+10000)
	dataDelivery := useCase.Deliveries[entity.Type]
	if dataDelivery == nil{
		return gohttplib.HTTP400("type not found")
	}
	useCase.repository.CreateVerification(entity, code)
	err := dataDelivery.Send(entity.Value, fmt.Sprintf("Verification code %s", code))
	return err
}

func (useCase *DefaultUseCase) SendCodeWithUser(user User, entity AuthorizationEntity) error {
	usrAttached := useCase.repository.GetForEntity(entity)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return entityAlreadyExists
		} else {
			return entityHasAlreadyUser
		}
	}
	return useCase.SendCode(entity)
}

func (useCase *DefaultUseCase) AuthenticateWithCode(entity AuthorizationEntity, code string) (*Response, error) {
	verification, err := useCase.getVerificationAndCompare(entity, code)
	if err != nil {
		return nil, err
	}
	usr := useCase.repository.GetForEntity(entity)
	if usr == nil {
		usr = useCase.repository.CreateForEntity(entity)
	}
	useCase.repository.DeleteVerification(verification.ID)
	return useCase.generateResponseFor(usr, nil)
}

func (useCase *DefaultUseCase) getVerificationAndCompare(entity AuthorizationEntity, code string) (*Verification, error) {
	verification := useCase.repository.GetVerificationForEntity(entity)
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

func (useCase *DefaultUseCase) RemoveAuthenticationEntity(user User, entity AuthorizationEntity) error {
	if len(user.Entities) == 1 {
		return cantDeleteLastEntity
	}
	foundIdx := useCase.foundEntityInUser(user, entity)
	if foundIdx == -1 {
		return gohttplib.HTTP404(entity.Value)
	}
	usrEntities := user.Entities
	usrEntities = append(usrEntities[:foundIdx], usrEntities[foundIdx+1:]...)
	user.Entities = usrEntities
	useCase.repository.Save(&user)
	return nil
}

func (useCase *DefaultUseCase) AddSocialAuthenticationEntity(user *User, socialProvider string, token string) (*User, error) {
	result, err := useCase.getInfoFromProvider(socialProvider, token)
	if err != nil {
		return nil, err
	}
	usrAttached := useCase.repository.GetForSocial(result)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return nil, entityAlreadyExists
		} else {
			return nil, entityHasAlreadyUser
		}
	}
	useCase.appendNewEntitiesFromSocialToUserIfNeed(user, result)
	return user, nil
}

func (useCase *DefaultUseCase) VerifyAuthenticationEntity(user *User, entity AuthorizationEntity, code string) (*User, error) {
	usrAttached := useCase.repository.GetForEntity(entity)
	if usrAttached != nil {
		if usrAttached.ID == user.ID {
			return nil, entityAlreadyExists
		} else {
			return nil, entityHasAlreadyUser
		}
	}
	verification, err := useCase.getVerificationAndCompare(entity, code)
	if err != nil {
		return nil, err
	}
	usrEntities := user.Entities
	usrEntities = append(usrEntities, entity)
	user.Entities = usrEntities
	useCase.repository.Save(user)
	useCase.repository.DeleteVerification(verification.ID)
	return user, nil
}

func (useCase *DefaultUseCase) findNewEntitiesInSocialProviderResult(old []AuthorizationEntity, result *ProviderResult) []AuthorizationEntity {
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

func (useCase *DefaultUseCase) GetValidModelFromToken(token string) *User {
	userData, err := useCase.getUserDataFromToken(token)
	if err != nil {
		return nil
	}
	model := useCase.repository.GetById(userData["id"].(string))
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
