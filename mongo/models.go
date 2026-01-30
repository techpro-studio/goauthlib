package mongo

import (
	auth "github.com/techpro-studio/goauthlib"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type mongoUser struct {
	ID       bson.ObjectID              `bson:"_id"`
	Entities []mongoAuthorizationEntity `bson:"entities"`
	Info     map[string]any             `bson:"info,omitempty"`
	Deleted  bool                       `bson:"deleted"`
	Services []string                   `bson:"services"`
}

type mongoAuthorizationEntity struct {
	Value string `bson:"value"`
	Type  string `bson:"type"`
}

func toDomainEntity(m mongoAuthorizationEntity) auth.AuthorizationEntity {
	return auth.AuthorizationEntity{
		Type:  m.Type,
		Value: m.Value,
	}
}

func toMongoEntity(e auth.AuthorizationEntity) mongoAuthorizationEntity {
	return mongoAuthorizationEntity{
		Value: e.Value,
		Type:  e.Type,
	}
}

func toDomainUser(m *mongoUser) *auth.User {
	if m == nil {
		return nil
	}
	var entities []auth.AuthorizationEntity
	for _, e := range m.Entities {
		entities = append(entities, toDomainEntity(e))
	}
	return &auth.User{
		ID:       m.ID.Hex(),
		Entities: entities,
		Info:     m.Info,
	}
}

func toMongoUser(u *auth.User) *mongoUser {
	if u == nil {
		return nil
	}
	var entities []mongoAuthorizationEntity
	for _, e := range u.Entities {
		entities = append(entities, toMongoEntity(e))
	}
	id, err := bson.ObjectIDFromHex(u.ID)
	if err != nil {
		panic(err)
	}
	return &mongoUser{
		ID:       id,
		Entities: entities,
		Info:     u.Info,
	}
}

type mongoVerification struct {
	ID              bson.ObjectID `bson:"_id"`
	Code            string        `bson:"code"`
	Destination     string        `bson:"destination"`
	DestinationType string        `bson:"destination_type"`
	Timestamp       int64         `json:"timestamp"`
}

func toMongoVerification(v *auth.Verification) *mongoVerification {
	id, err := bson.ObjectIDFromHex(v.ID)
	if err != nil {
		panic(err)
	}
	return &mongoVerification{
		ID:              id,
		Code:            v.Code,
		Destination:     v.Destination,
		DestinationType: v.DestinationType,
		Timestamp:       v.Timestamp,
	}
}

func toDomainVerification(m *mongoVerification) *auth.Verification {
	return &auth.Verification{
		ID:              m.ID.Hex(),
		Code:            m.Code,
		Destination:     m.Destination,
		DestinationType: m.DestinationType,
		Timestamp:       m.Timestamp,
	}
}
