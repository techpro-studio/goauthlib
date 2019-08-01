package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"net/http"
)

func (t *Transport) RegisterInRouter(router gohttplib.Router) {
	usrMiddleware := UserMiddlewareFactory(t.useCase)
	router.Post("/auth/verify", t.defaultMiddleWare(http.HandlerFunc(t.AuthenticateWithCodeHandler)))
	router.Post("/auth/social", t.defaultMiddleWare(http.HandlerFunc(t.AuthenticateViaSocialProviderHandler)))
	router.Post("/auth/send", t.defaultMiddleWare(http.HandlerFunc(t.SendCodeHandler)))
	router.Post("/user/entity/remove", t.defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.RemoveAuthenticationEntityHandler))))
	router.Post("/user/entity/social", t.defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.AddSocialAuthenticationEntityHandler))))
	router.Post("/user/entity/verify", t.defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.VerifyAuthenticationEntityHandler))))
	router.Post("/user/entity/send", t.defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.SendCodeWithUserHandler))))
}
