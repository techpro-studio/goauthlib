package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"net/http"
)


type Transport struct {
	useCase           UseCase
	defaultMiddleWare gohttplib.Middleware
}

func NewTransport(useCase UseCase, defaultMiddleWare gohttplib.Middleware) *Transport {
	return &Transport{useCase: useCase, defaultMiddleWare: defaultMiddleWare}
}

func (t *Transport) withBody(w http.ResponseWriter, r *http.Request, handler func(body map[string]interface{})(interface{}, error)){
	body, err := gohttplib.GetBody(r)
	if err != nil{
		err.(*gohttplib.ServerError).Write(w)
		return
	}
	resp, err := handler(body)
	gohttplib.WriteJsonOrError(w, resp,  200, gohttplib.SafeConvertToServerError(err))
}

func (t *Transport) withAuthorizationEntity(w http.ResponseWriter, r *http.Request, handler func(entity AuthorizationEntity)(interface{}, error)){
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		entity, err := GetAuthorizationEntityFromBody(body)
		if err != nil{
			return nil, err
		}
		return handler(*entity)
	})
}

func (t *Transport) withSocial(w http.ResponseWriter, r *http.Request, handler func(providerType string, token string)(interface{}, error)){
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		providerType, token, err := GetSocialProviderInfo(body)
		if err != nil{
			return nil, err
		}
		return handler(providerType, token)
	})
}

func (t *Transport) withAuthorizationEntityAndCode(w http.ResponseWriter, r *http.Request, handler func(entity AuthorizationEntity, code string)(interface{}, error)){
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		entity, err := GetAuthorizationEntityFromBody(body)
		code, err := GetCode(body)
		if err != nil{
			return nil, err
		}
		return handler(*entity, code)
	})
}


func (t *Transport)CurrentUserHandler(w http.ResponseWriter, r *http.Request){
	gohttplib.WriteJson(w, GetUserFromRequestWithPanic(r), 200)
}

func (t *Transport) AuthenticateViaSocialProviderHandler(w http.ResponseWriter, r *http.Request) {
	t.withSocial(w, r, func(providerType string, token string) (i interface{}, e error) {
		return t.useCase.AuthenticateViaSocialProvider(providerType, token)
	})
}

func (t *Transport) SendCodeHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r , func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.SendCode(entity)
	})
}

func (t *Transport) AuthenticateWithCodeHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntityAndCode(w, r, func(entity AuthorizationEntity, code string) (i interface{}, e error) {
		return t.useCase.AuthenticateWithCode(entity, code)
	})
}

func (t *Transport) RemoveAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r, func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.RemoveAuthenticationEntity(GetUserFromRequestWithPanic(r), entity)
	})
}

func (t *Transport) AddSocialAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withSocial(w, r, func(providerType string, token string) (i interface{}, e error) {
		usr := GetUserFromRequestWithPanic(r)
		return t.useCase.AddSocialAuthenticationEntity(&usr, providerType, token)
	})
}

func (t *Transport) SendCodeWithUserHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r, func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.SendCodeWithUser(GetUserFromRequestWithPanic(r), entity)
	})
}

func (t *Transport) VerifyAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntityAndCode(w, r, func(entity AuthorizationEntity, code string) (i interface{}, e error) {
		usr := GetUserFromRequestWithPanic(r)
		return t.useCase.VerifyAuthenticationEntity(&usr, entity, code)
	})
}







