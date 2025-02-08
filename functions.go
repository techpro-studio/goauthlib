package goauthlib

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strings"
)

func SafeExtractUserIdFromHeader(h http.Header, secret string) *string {
	// Check if Authorization header exists
	authHeader, ok := h["Authorization"]
	if !ok || len(authHeader) == 0 {
		log.Printf("Authorization header is missing")
		return nil
	}

	// Split the Authorization header into parts
	tokenParts := strings.Split(authHeader[0], " ")
	if len(tokenParts) != 2 || tokenParts[0] != "JWT" {
		log.Printf("Invalid Authorization header format")
		return nil
	}

	token := tokenParts[1]

	// Parse the JWT token
	tokenObj, err := jwt.ParseWithClaims(token, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the expected signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				log.Printf("Token is expired")
				return nil
			}
		}
		log.Printf("Failed to parse token: %s", err.Error())
		return nil
	}

	if !tokenObj.Valid {
		log.Printf("Token is invalid")
		return nil
	}

	// Safely access the claims
	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Invalid claims type")
		return nil
	}

	user, ok := claims["user"].(map[string]interface{})
	if !ok {
		log.Printf("User claim is missing or invalid")
		return nil
	}

	userIdFromJwt, ok := user["id"].(string)
	if !ok {
		log.Printf("User ID is missing or invalid")
		return nil
	}

	return &userIdFromJwt
}
