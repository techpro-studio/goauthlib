package goauthlib

//Response is sent back
type Response struct {
	Token    string                 `json:"token"`
	User     User                   `json:"user"`
	UserInfo map[string]interface{} `json:"user_info"`
}

var OK = map[string]int {"ok": 1}

const (
	EntityTypeEmail    = "email"
	EntityTypePhone    = "phone"
	EntityTypeFacebook = "facebook"
)

// User is an object of auth service
type User struct {
	ID       string                `json:"id"`
	Entities []AuthorizationEntity `json:"entities"`
}

type AuthorizationEntity struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}



func (e AuthorizationEntity) isEqual(another interface{}) bool {
	anotherEntity, ok := another.(AuthorizationEntity)
	if !ok {
		return false
	}
	return anotherEntity.Value == e.Value && anotherEntity.Type == e.Type
}

func (e AuthorizationEntity) GetHash()string {
	return e.Type+e.Value
}

type Verification struct{
	ID string `bson:"_id"`
	Code string `bson:"code"`
	Destination string `bson:"destination"`
	DestinationType string `bson:"destination_type"`
	Created int64 `json:"created"`
}
