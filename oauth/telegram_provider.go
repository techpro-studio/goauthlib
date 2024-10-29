package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type TelegramProvider struct {
	botToken string
}

func NewTelegramProvider(botToken string) *TelegramProvider {
	return &TelegramProvider{botToken: botToken}
}

func computeHmacSha256(key []byte, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// isJSONString checks if a string is a valid JSON string.
func isJSONString(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
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

	var secretKey []byte

	// If 'user' parameter exists and is a JSON string, it's from WebAppData
	userValue := valuesCopy.Get("user")
	if userValue != "" && isJSONString(userValue) {
		// Compute secret key for WebAppData
		secretKey = computeHmacSha256([]byte("WebAppData"), []byte(botToken))
	} else {
		// Compute secret key as SHA256 hash of the bot token
		sum := sha256.Sum256([]byte(botToken))
		secretKey = sum[:]
	}

	// Compute HMAC-SHA256 of the data check string using the secret key
	hmacHash := hmac.New(sha256.New, secretKey)
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

	var firstName string
	var lastName string
	var userName string
	var id string
	user := params.Get("user")
	const kFirstName = "first_name"
	const kId = "id"
	const kLastName = "last_name"
	const kUserName = "username"
	if user == "" {
		id = params.Get(kId)
		firstName = params.Get(kFirstName)
		lastName = params.Get(kLastName)
		userName = params.Get(kUserName)
	} else {
		var usr map[string]any
		err := json.Unmarshal([]byte(user), &usr)
		if err != nil {
			return nil, err
		}
		firstName = usr[kFirstName].(string)
		lastName = usr[kLastName].(string)
		userName = usr[kUserName].(string)
		id = strconv.Itoa(int(usr[kId].(float64)))
	}

	err = VerifyTelegramData(params, t.botToken)

	if err != nil {
		return nil, err
	}

	return &ProviderResult{
		ID:    id,
		Type:  "telegram",
		Email: "",
		Phone: "",
		Raw: map[string]interface{}{
			kFirstName:                      firstName,
			kLastName:                       lastName,
			fmt.Sprintf("tg_%s", kUserName): userName,
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
