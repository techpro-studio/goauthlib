package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/gohttplib/utils"
	"github.com/techpro-studio/gohttplib/validator"
)

func MakeAuthorizationEntityVMap() validator.VMap {
	return validator.VMap{
		"value": validator.RequiredStringValidators("value"),
	}
}

func MakeCodeVMap() validator.VMap {
	return validator.VMap{
		"code": validator.RequiredStringValidators("code", validator.StringLengthValidator(5, "code")),
	}
}

func MakeSocialProviderVMap() validator.VMap {
	return validator.VMap{
		"provider": validator.RequiredStringValidators("provider"),
		"payload_type": validator.RequiredStringValidators("payload_type", validator.StringContainsValidator("payload_type", []string{
			"token", "code"})),
		"payload": validator.RequiredStringValidators("payload"),
	}
}

type SocialProviderPayload struct {
	Provider    string
	PayloadType string
	Payload     string
	Remaining   map[string]interface{}
}

func GetSocialProviderPayloadInfo(body map[string]interface{}) (*SocialProviderPayload, error) {
	validated, err := validator.ValidateBody(body, MakeSocialProviderVMap())
	if err != nil {
		return nil, err
	}
	remaining := map[string]interface{}{}
	for key, value := range body {
		if key != "provider" && key != "payload" && key != "payload_type" {
			remaining[key] = value
		}
	}
	result := SocialProviderPayload{
		Provider:    validated["provider"].(string),
		Payload:     validated["payload"].(string),
		PayloadType: validated["payload_type"].(string),
		Remaining:   remaining,
	}
	return &result, nil
}

func GetCode(body map[string]interface{}) (string, error) {
	validated, err := validator.ValidateBody(body, MakeCodeVMap())
	if err != nil {
		return "", err
	}
	return validated["code"].(string), nil
}

func GetAuthorizationEntityFromBody(body map[string]interface{}) (*AuthorizationEntity, error) {
	validated, err := validator.ValidateBody(body, MakeAuthorizationEntityVMap())
	if err != nil {
		return nil, err
	}
	var _type string
	value := validated["value"].(string)
	if utils.IsValidEmail(value) {
		_type = EntityTypeEmail
	} else if utils.IsValidPhone(value) {
		_type = EntityTypePhone
		return nil, gohttplib.NewServerError(400, "CREDENTIAL_PHONE_TEMPORARY_UNAVAILABLE", "Phone credentials temporary unavailable", "value", nil)
	} else {
		return nil, gohttplib.NewServerError(400, "INVALID_CREDENTIAL", "Invalid credential. Should be phone or email.", "value", nil)
	}

	return &AuthorizationEntity{
		Value: value,
		Type:  _type,
	}, nil
}
