package goauthlib

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"strings"
)

func GenerateTokenFromModel(model User, blinder string, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	hash := GenerateTokenHash(model, blinder)

	claims := struct {
		Hash string `json:"hash"`
		User User   `json:"user"`
		jwt.RegisteredClaims
	}{hash,
		model,
		jwt.RegisteredClaims{
			Issuer: "auth",
		},
	}
	tokenObj := jwt.NewWithClaims(signingMethod, claims)

	token, err := tokenObj.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return token, nil
}

func GetClaimsFromToken(token string, currentSigningMethod jwt.SigningMethod, currentSigningKey any) (map[string]any, error) {
	tokenObj, err := jwt.ParseWithClaims(token, &jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != currentSigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return currentSigningKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Printf("Token is expired")
			return nil, err
		}

		log.Printf("Failed to parse token: %s", err.Error())
		return nil, err
	}

	if !tokenObj.Valid {
		log.Printf("Token is invalid")
		return nil, errors.New("invalid token")
	}

	// Safely access the claims
	claims, ok := tokenObj.Claims.(*jwt.MapClaims)
	if !ok {
		log.Printf("Invalid claims type")
	}
	return *claims, nil
}

func GenerateTokenHash(model User, blinder string) string {
	sha := sha3.New256()
	bytes, err := hex.DecodeString(model.ID)
	if err != nil {
		panic(err)
	}
	bytes = append(bytes, []byte(blinder)...)
	_, err = sha.Write(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(sha.Sum(nil))
}

func SafeExtractUserIdFromHeader(h http.Header, currentSigningMethod jwt.SigningMethod, signingKey any) (string, error) {
	// Check if Authorization header exists
	authHeader, ok := h["Authorization"]
	if !ok || len(authHeader) == 0 {
		return "", errors.New("authorization header is missing")
	}

	// Split the Authorization header into parts
	tokenParts := strings.Split(authHeader[0], " ")
	if len(tokenParts) != 2 || tokenParts[0] != "JWT" {
		return "", errors.New("invalid Authorization header format")
	}

	token := tokenParts[1]

	claims, err := GetClaimsFromToken(token, currentSigningMethod, signingKey)
	if err != nil {
		return "", err
	}

	user, ok := claims["user"].(map[string]any)
	if !ok {
		return "", errors.New("user claim is missing or invalid")
	}

	userIdFromJwt, ok := user["id"].(string)
	if !ok {
		return "", errors.New("user ID is missing or invalid")
	}

	return userIdFromJwt, nil
}

func GetValidUserFromToken(token string, config Config) (*User, error) {
	claims, err := GetClaimsFromToken(token, config.signingMethod, config.signingKey)
	if err != nil {
		return nil, err
	}
	userBytes, err := json.Marshal(claims["user"])
	if err != nil {
		return nil, err
	}
	var user User
	err = json.Unmarshal(userBytes, &user)
	if err != nil {
		return nil, err
	}

	if GenerateTokenHash(user, config.blinder) != claims["hash"] {
		return nil, errors.New("invalid token hash")
	}
	return &user, nil
}
