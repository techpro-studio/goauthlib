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

func VerifyTelegramData(values map[string]any, botToken string) error {
	// Extract the 'hash' parameter
	receivedHash, ok := values["hash"].(string)
	if !ok || receivedHash == "" {
		return errors.New("no hash parameter provided")
	}

	// Remove 'hash' from the parameters to avoid including it in the data check string
	valuesCopy := map[string]any{}
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
		var stringValue string
		floatValue, floatOk := valuesCopy[key].(float64)
		if floatOk {
			stringValue = strconv.Itoa(int(floatValue))
		} else {
			stringValue = valuesCopy[key].(string)
		}

		dataCheckStrings = append(dataCheckStrings, fmt.Sprintf("%s=%s", key, stringValue))
	}
	dataCheckString := strings.Join(dataCheckStrings, "\n")

	var secretKey []byte

	// If 'user' parameter exists and is a JSON string, it's from WebAppData
	userValue, ok := valuesCopy["user"].(string)
	if ok && userValue != "" && isJSONString(userValue) {
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

func getStringSafe(m map[string]interface{}, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return "" // or a default value
}

func extractTelegramParameters(infoToken string) (map[string]any, error) {
	result := map[string]any{}
	err := json.Unmarshal([]byte(infoToken), &result)
	if err == nil {
		return result, nil
	}
	urlParams, err := url.ParseQuery(infoToken)
	for key, value := range urlParams {
		result[key] = value[0]
	}
	return result, nil
}

type UserData struct {
	Id        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
}

const kFirstName = "first_name"
const kLastName = "last_name"
const kUserName = "username"
const kId = "id"

func mapUserData(usr map[string]any) UserData {
	var id string
	id, ok := usr[kId].(string)
	if !ok {
		id = strconv.Itoa(int(usr[kId].(float64)))
	}
	return UserData{
		Id:        id,
		FirstName: getStringSafe(usr, kFirstName),
		LastName:  getStringSafe(usr, kLastName),
		Username:  getStringSafe(usr, kUserName),
	}
}

func (t *TelegramProvider) GetInfoByToken(ctx context.Context, infoToken string) (*ProviderResult, error) {

	if strings.HasPrefix(infoToken, "?") {
		infoToken = infoToken[1:]
	}

	params, err := extractTelegramParameters(infoToken)

	if err != nil {
		return nil, err
	}

	user, userOk := params["user"].(string)

	var userData UserData
	if userOk && user != "" {
		var usr map[string]any
		err := json.Unmarshal([]byte(user), &usr)
		if err != nil {
			return nil, err
		}
		userData = mapUserData(usr)
	} else {
		userData = mapUserData(params)
	}

	err = VerifyTelegramData(params, t.botToken)

	if err != nil {
		return nil, err
	}

	return &ProviderResult{
		ID:    userData.Id,
		Type:  "telegram",
		Email: "",
		Phone: "",
		Raw: map[string]interface{}{
			kFirstName:                      userData.FirstName,
			kLastName:                       userData.LastName,
			fmt.Sprintf("tg_%s", kUserName): userData.Username,
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
