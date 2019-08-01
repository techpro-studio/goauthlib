package social

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/goauthlib"
	"github.com/techpro-studio/gohttplib/utils"
	"io/ioutil"
	"net/http"
	"time"
)

//FacebookProvider get info from facebook
type FacebookProvider struct {
	UseTokenForBusinessAsID bool
	Scope                   string
}

func NewFacebookProvider(UseTokenForBusinessAsID bool, Scope string) *FacebookProvider {
	return &FacebookProvider{UseTokenForBusinessAsID: UseTokenForBusinessAsID, Scope: Scope}
}

func (provider *FacebookProvider) getRawData(token string, fields string, photoDimension int) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	url := fmt.Sprintf(
		"https://graph.facebook.com/v3.0/me?fields=%s&access_token=%s", fields, token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		cancel()
		return nil, gohttplib.HTTP400(err.Error())
	}
	req.WithContext(ctx)
	response := map[string]interface{}{}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	buf, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(buf, &response)
	if err != nil {
		return nil, gohttplib.HTTP400(err.Error())
	}
	response["avatar"] = fmt.Sprintf("https://graph.facebook.com/%s/picture?type=square&width=%d&height=%d", response["id"], photoDimension, photoDimension)
	return response, nil
}

//GetInfoByToken implementation of Provider
func (provider *FacebookProvider) GetInfoByToken(token string) (*ProviderResult, error) {
	raw, err := provider.getRawData(token, provider.Scope, 500)
	if err != nil {
		return nil, err
	}
	result := ProviderResult{Raw: raw, Type:goauthlib.EntityTypeFacebook}
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
