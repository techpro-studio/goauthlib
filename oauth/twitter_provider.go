package oauth

import (
	"context"
	"errors"
	"fmt"
	"github.com/michimani/gotwi"
	"github.com/michimani/gotwi/fields"
	"github.com/michimani/gotwi/user/userlookup"
	"github.com/michimani/gotwi/user/userlookup/types"
	"strings"
)

type TwitterProvider struct {
	apiKey    string
	apiSecret string
}

func NewTwitterProvider(apiKey string, apiSecret string) *TwitterProvider {
	return &TwitterProvider{apiKey, apiSecret}
}

func (t TwitterProvider) GetInfoByToken(ctx context.Context, infoToken string) (*ProviderResult, error) {
	tokens := strings.Split(infoToken, ":")
	if len(tokens) != 3 {
		return nil, errors.New("invalid token")
	}
	in := &gotwi.NewClientInput{
		AuthenticationMethod: gotwi.AuthenMethodOAuth1UserContext,
		OAuthToken:           tokens[0],
		OAuthTokenSecret:     tokens[1],
		APIKey:               t.apiKey,
		APIKeySecret:         t.apiSecret,
	}

	c, err := gotwi.NewClient(in)
	if err != nil {

		return nil, err
	}

	p := &types.GetMeInput{
		UserFields: fields.UserFieldList{
			fields.UserFieldCreatedAt,
		},
		TweetFields: fields.TweetFieldList{
			fields.TweetFieldCreatedAt,
		},
	}

	user, err := userlookup.GetMe(context.Background(), c, p)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &ProviderResult{
		ID:     *user.Data.ID,
		Type:   "twitter",
		Tokens: Tokens{},
		Raw: map[string]any{
			"name":     *user.Data.Name,
			"id":       *user.Data.ID,
			"username": *user.Data.Username,
		},
	}, nil
}

func (t *TwitterProvider) ExtractAvatarUrl(ctx context.Context, id string) (*string, error) {
	return nil, nil
}

func (t TwitterProvider) ExchangeCode(ctx context.Context, code string) (*Result, error) {
	return nil, nil
}

func (t TwitterProvider) RevokeTokens(ctx context.Context, tokens Tokens) error {
	return nil
}
