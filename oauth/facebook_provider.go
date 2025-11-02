package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/techpro-studio/gohttplib/utils"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// FacebookProvider get info from facebook
type FacebookProvider struct {
	UseTokenForBusinessAsID bool
	oauthConfig             *oauth2.Config
}

func (provider *FacebookProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	return ExchangeCodeUsingProvider(provider.oauthConfig, ctx, code)
}

func (provider *FacebookProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	return nil
}

func (provider *FacebookProvider) GetOAuthConfig() *oauth2.Config {
	return provider.oauthConfig
}

func NewFacebookProvider(UseTokenForBusinessAsID bool, oauthConfig *oauth2.Config) *FacebookProvider {
	return &FacebookProvider{UseTokenForBusinessAsID: UseTokenForBusinessAsID, oauthConfig: oauthConfig}
}

func (provider *FacebookProvider) ExtractAvatarUrl(ctx context.Context, id string) (*string, error) {
	return nil, nil
}

func (provider *FacebookProvider) getRawData(token string, photoDimension int) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := fmt.Sprintf(
		"https://graph.facebook.com/v16.0/me?fields=email,name,token_for_business,id&access_token=%s", token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.WithContext(ctx)
	response := map[string]interface{}{}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	buf, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(buf, &response)
	if err != nil {
		log.Printf(string(buf))
		return nil, err
	}
	response["avatar"] = fmt.Sprintf("https://graph.facebook.com/%s/picture?type=square&width=%d&height=%d", response["id"], photoDimension, photoDimension)
	return response, nil
}

// GetInfoByToken implementation of SocialProvider
func (provider *FacebookProvider) GetInfoByToken(ctx context.Context, token string) (*ProviderResult, error) {
	raw, err := provider.getRawData(token, 500)
	if err != nil {
		return nil, err
	}
	result := ProviderResult{Raw: raw, Type: EntityTypeOAuthFacebook}
	result.ID = raw["id"].(string)
	tokenForBusiness, ok := raw["token_for_business"].(string)
	if provider.UseTokenForBusinessAsID && ok {
		result.ID = tokenForBusiness
	}
	email, ok := raw["email"].(string)
	if ok && utils.IsValidEmail(email) {
		result.Email = email
	}
	phone, ok := raw["phone"].(string)
	if ok && utils.IsValidPhone(phone) {
		result.Phone = phone
	}
	return &result, nil
}
