package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"net/http"
)

func RegisterPrivateInRouter(t *Transport, router gohttplib.Router, usrMiddleware gohttplib.Middleware, defaultMiddleWare gohttplib.Middleware) {
	router.Post("/auth/verify", defaultMiddleWare(http.HandlerFunc(t.AuthenticateWithCodeHandler)))
	router.Post("/auth/social", defaultMiddleWare(http.HandlerFunc(t.AuthenticateViaSocialProviderHandler)))
	router.Get("/user", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.CurrentUserHandler))))
	router.Post("/auth/temp", defaultMiddleWare(http.HandlerFunc(t.AuthWithTempToken)))
}

func RegisterPublicInRouter(t *Transport, router gohttplib.Router, usrMiddleware gohttplib.Middleware, defaultMiddleWare gohttplib.Middleware) {
	router.Get("/auth/temp", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.GetTempToken))))
	router.Post("/delete/send", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.SendVerificationCodeHandler))))
	router.Post("/delete", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.VerifyDeleteHandler))))
	router.Post("/force-delete", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.ForceDeleteHandler))))
	router.Patch("/user/info", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.PatchInfoHandler))))
	router.Post("/auth/send", defaultMiddleWare(http.HandlerFunc(t.SendCodeHandler)))
	router.Post("/user/entity/remove", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.RemoveAuthenticationEntityHandler))))
	router.Post("/user/entity/social", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.AddSocialAuthenticationEntityHandler))))
	router.Post("/user/entity/verify", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.VerifyAuthenticationEntityHandler))))
	router.Post("/user/entity/send", defaultMiddleWare(usrMiddleware(http.HandlerFunc(t.SendCodeWithUserHandler))))
}
