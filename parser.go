package goauthlib

import (
	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/gohttplib/utils"
	"github.com/techpro-studio/gohttplib/validator"
)

func MakeAuthorizationEntityVMap()validator.VMap {
	return validator.VMap{
		"type": validator.RequiredStringValidators("type", validator.StringContainsValidator("type", []string{
			EntityTypePhone, EntityTypeEmail})),
		"value": validator.RequiredStringValidators("value"),
	}
}

func MakeCodeVMap()validator.VMap {
	return validator.VMap{
		"code": validator.RequiredStringValidators("code", validator.StringLengthValidator(5, "code")),
	}
}

func MakeSocialProviderVMap()validator.VMap {
	return validator.VMap{
		"type": validator.RequiredStringValidators("type"),
		"token": validator.RequiredStringValidators("token"),
	}
}

func GetSocialProviderInfo(body map[string]interface{}) (string, string, error){
	validated, err := validator.ValidateBody(body, MakeAuthorizationEntityVMap())
	if err != nil {
		return "", "", err
	}
	return validated["type"].(string), validated["token"].(string), nil
}

func GetCode(body map[string]interface{}) (string, error){
	validated, err := validator.ValidateBody(body, MakeAuthorizationEntityVMap())
	if err != nil {
		return "", err
	}
	return validated["code"].(string), nil
}

func GetAuthorizationEntityFromBody(body map[string]interface{}) (*AuthorizationEntity, error){
	validated, err := validator.ValidateBody(body, MakeAuthorizationEntityVMap())
	if err != nil {
		return nil, err
	}
	_type := validated["type"].(string)
	value := validated["value"].(string)
	switch _type {
	case EntityTypeEmail:
		if !utils.IsValidEmail(value){
			return nil, gohttplib.HTTP400("Invalid email")
		}
	default:
		if !utils.IsValidPhone(value){
			return nil, gohttplib.HTTP400("Invalid phone")
		}
	}
	return &AuthorizationEntity{
		Value: value,
		Type: _type,
	}, nil
}


