package goauthlib

import (
	"context"
	"github.com/techpro-studio/gohttplib"
	"net/http"
	"strings"
)

const CurrentUserContextKey = "current_user_key"

func UserMiddlewareFactory(useCase UseCase) gohttplib.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			tokenStr := GetTokenFromRequest(req)
			if tokenStr == "" {
				gohttplib.HTTP401().Write(w)
				return
			}
			user := useCase.GetValidModelFromToken(tokenStr)
			if user ==  nil{
				gohttplib.HTTP401().Write(w)
				return
			}
			ctx := context.WithValue(req.Context(), CurrentUserContextKey, user)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}


func GetTokenFromRequest(req *http.Request)string{
	tokenStr := ""
	if AuthHeader := req.Header.Get("Authorization"); AuthHeader != "" {
		tokenStr = strings.Split(AuthHeader, " ")[1]
	}
	if tokenStr == "" {
		token :=  gohttplib.GetParameterFromURLInRequest(req, "token")
		if token != nil {
			tokenStr = *token
		}
	}
	return tokenStr
}

func GetUserFromRequestWithPanic(req *http.Request) User {
	usr := GetUserFromRequest(req)
	if usr == nil{
		panic("No current user")
	}
	return *usr
}

func GetUserFromRequest(req *http.Request) *User {
	user, ok := req.Context().Value(CurrentUserContextKey).(*User)
	if !ok {
		return nil
	}
	return user
}

