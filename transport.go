package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/gohttplib/validator"
	"net/http"
)

type Transport struct {
	useCase UseCase
}

func NewTransport(useCase UseCase) *Transport {
	return &Transport{useCase: useCase}
}

func (t *Transport) withBody(w http.ResponseWriter, r *http.Request, handler func(body map[string]interface{}) (interface{}, error)) {
	body, err := gohttplib.GetBody(r)
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(w)
		return
	}
	resp, err := handler(body)
	gohttplib.WriteJsonOrError(w, resp, 200, err)
}

func (t *Transport) withAuthorizationEntity(w http.ResponseWriter, r *http.Request, handler func(entity AuthorizationEntity) (interface{}, error)) {
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		entity, err := GetAuthorizationEntityFromBody(body)
		if err != nil {
			return nil, err
		}
		return handler(*entity)
	})
}

func (t *Transport) withOAuthPayload(w http.ResponseWriter, r *http.Request, handler func(payload SocialProviderPayload) (interface{}, error)) {
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		providerPayload, err := GetSocialProviderPayloadInfo(body)
		if err != nil {
			return nil, err
		}
		return handler(*providerPayload)
	})
}

func (t *Transport) withAuthorizationEntityAndCode(w http.ResponseWriter, r *http.Request, handler func(entity AuthorizationEntity, code string) (interface{}, error)) {
	t.withBody(w, r, func(body map[string]interface{}) (i interface{}, e error) {
		entity, err := GetAuthorizationEntityFromBody(body)
		code, err := GetCode(body)
		if err != nil {
			return nil, err
		}
		return handler(*entity, code)
	})
}

func (t *Transport) CurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	gohttplib.WriteJson(w, GetUserFromRequestWithPanic(r), 200)
}

func (t *Transport) AuthenticateViaSocialProviderHandler(w http.ResponseWriter, r *http.Request) {
	t.withOAuthPayload(w, r, func(payload SocialProviderPayload) (i interface{}, e error) {
		return t.useCase.AuthenticateViaSocialProvider(r.Context(), payload)
	})
}

func (t *Transport) SendCodeHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r, func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.SendCode(r.Context(), entity)
	})
}

func (t *Transport) SendVerificationCodeHandler(writer http.ResponseWriter, request *http.Request) {
	usr := GetUserFromRequestWithPanic(request)
	err := t.useCase.SendVerificationCode(request.Context(), usr, deleteAccountAction)
	gohttplib.WriteJsonOrError(writer, OK, 200, err)
}

func (t *Transport) VerifyDeleteHandler(writer http.ResponseWriter, request *http.Request) {
	usr := GetUserFromRequestWithPanic(request)
	body, err := gohttplib.GetBody(request)
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(writer)
		return
	}
	code, err := GetCode(body)
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(writer)
		return
	}
	err = t.useCase.VerifyDelete(request.Context(), usr, code)
	gohttplib.WriteJsonOrError(writer, OK, 200, err)
}

func (t *Transport) ForceDeleteHandler(writer http.ResponseWriter, request *http.Request) {
	usr := GetUserFromRequestWithPanic(request)
	err := t.useCase.ForceDelete(request.Context(), usr)
	gohttplib.WriteJsonOrError(writer, OK, 200, err)
}

func (t *Transport) AuthenticateWithCodeHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntityAndCode(w, r, func(entity AuthorizationEntity, code string) (i interface{}, e error) {
		return t.useCase.AuthenticateWithCode(r.Context(), entity, code)
	})
}

func (t *Transport) RemoveAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r, func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.RemoveAuthenticationEntity(r.Context(), GetUserFromRequestWithPanic(r), entity)
	})
}

func (t *Transport) AddSocialAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withOAuthPayload(w, r, func(payload SocialProviderPayload) (i interface{}, e error) {
		usr := GetUserFromRequestWithPanic(r)
		return t.useCase.AddSocialAuthenticationEntity(r.Context(), &usr, payload)
	})
}

func (t *Transport) SendCodeWithUserHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntity(w, r, func(entity AuthorizationEntity) (i interface{}, e error) {
		return OK, t.useCase.SendCodeWithUser(r.Context(), GetUserFromRequestWithPanic(r), entity)
	})
}

func (t *Transport) VerifyAuthenticationEntityHandler(w http.ResponseWriter, r *http.Request) {
	t.withAuthorizationEntityAndCode(w, r, func(entity AuthorizationEntity, code string) (i interface{}, e error) {
		usr := GetUserFromRequestWithPanic(r)
		return t.useCase.VerifyAuthenticationEntity(r.Context(), &usr, entity, code)
	})
}

func (t *Transport) PatchInfoHandler(w http.ResponseWriter, r *http.Request) {
	usr := GetUserFromRequestWithPanic(r)
	body, err := gohttplib.GetBody(r)
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(w)
		return
	}
	patched, err := t.useCase.PatchUserInfo(r.Context(), &usr, body)
	gohttplib.WriteJsonOrError(w, patched, 200, err)
}

func (t *Transport) GetTempToken(w http.ResponseWriter, r *http.Request) {
	usr := GetUserFromRequestWithPanic(r)
	token, err := t.useCase.GenerateTempTokenFor(r.Context(), usr)
	gohttplib.WriteJsonOrError(w, map[string]string{"token": token}, 200, err)
}

func (t *Transport) AuthWithTempToken(w http.ResponseWriter, r *http.Request) {
	payload, err := validator.GetValidatedBody(r, MakeTempTokenVMap())
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(w)
		return
	}
	response, err := t.useCase.AuthenticateWithTempToken(r.Context(), payload["token"].(string))
	gohttplib.WriteJsonOrError(w, response, 200, err)

}
