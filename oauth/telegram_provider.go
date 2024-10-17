package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
)

type TelegramProvider struct {
	botToken string
}

func NewTelegramProvider(botToken string) *TelegramProvider {
	return &TelegramProvider{botToken: botToken}
}

func VerifyTelegramData(values url.Values, botToken string) error {
	// Extract the 'hash' parameter
	receivedHash := values.Get("hash")
	if receivedHash == "" {
		return errors.New("No hash parameter provided")
	}

	// Remove 'hash' from the parameters to avoid including it in the data check string
	valuesCopy := url.Values{}
	for key, val := range values {
		if key != "hash" {
			valuesCopy[key] = val
		}
	}

	// Sort the parameters by key
	var keys []string
	for key := range valuesCopy {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Build the data check string
	var dataCheckStrings []string
	for _, key := range keys {
		// Join multiple values for the same key (if any)
		joinedValues := strings.Join(valuesCopy[key], ",")
		dataCheckStrings = append(dataCheckStrings, fmt.Sprintf("%s=%s", key, joinedValues))
	}
	dataCheckString := strings.Join(dataCheckStrings, "\n")

	// Compute the secret key as SHA256 hash of the bot token
	secretKey := sha256.Sum256([]byte(botToken))

	// Compute HMAC-SHA256 of the data check string using the secret key
	hmacHash := hmac.New(sha256.New, secretKey[:])
	hmacHash.Write([]byte(dataCheckString))
	computedHash := hmacHash.Sum(nil)

	// Convert computed hash to hexadecimal string
	computedHashHex := hex.EncodeToString(computedHash)

	// Compare the computed hash with the received hash (case-insensitive)
	if strings.EqualFold(computedHashHex, receivedHash) {
		return nil
	} else {
		fmt.Printf("Computed hash: %s\n", computedHashHex)
		fmt.Printf("Received hash: %s\n", receivedHash)
		return errors.New("invalid hash comparison")
	}
}

func (t *TelegramProvider) GetInfoByToken(ctx context.Context, infoToken string) (*ProviderResult, error) {

	if strings.HasPrefix(infoToken, "?") {
		infoToken = infoToken[1:]
	}

	params, err := url.ParseQuery(infoToken)
	if err != nil {
		return nil, err
	}

	err = VerifyTelegramData(params, t.botToken)

	if err != nil {
		return nil, err
	}

	return &ProviderResult{
		ID:    params.Get("id"),
		Type:  "telegram",
		Email: "",
		Phone: "",
		Raw: map[string]interface{}{
			"first_name": params.Get("first_name"),
			"last_name":  params.Get("last_name"),
			"username":   params.Get("username"),
		},
	}, nil
}

func (t *TelegramProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	return &Result{InfoToken: code}, nil
}

func (t *TelegramProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	log.Println("No need to do it now")
	return nil
}
