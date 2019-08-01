package mongo

import (
	"context"
	"github.com/techpro-studio/goauthlib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type Repository struct {
	Client *mongo.Client
}

func NewRepository(client *mongo.Client) *Repository {
	return &Repository{Client: client}
}

func (repo *Repository) GetVerificationForEntity(entity goauthlib.AuthorizationEntity) *goauthlib.Verification {
	return repo.getOneVerification(bson.M{"destination": entity.Value, "destination_type": entity.Type})
}

func (repo *Repository) CreateVerification(entity goauthlib.AuthorizationEntity, verificationCode string) *goauthlib.Verification {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := bson.M{"destination": entity.Value, "destination_type": entity.Type}
	m := mongoVerification{
		ID:              primitive.NewObjectID(),
		Code:            verificationCode,
		Destination:     entity.Value,
		DestinationType: entity.Type,
		Created:         time.Now().Unix(),
	}
	yes := true
	_, err := repo.Client.Database(dbName).Collection(verificationCollection).UpdateOne(ctx,  q, m, &options.UpdateOptions{Upsert: &yes})
	if err != nil{
		panic(err)
	}
	return toDomainVerification(&m)
}

func (repo *Repository) GetForSocial(result *goauthlib.ProviderResult) *goauthlib.User {
	or := []bson.M{{"entities.$.type": result.Type, "entities.$.value": result.ID}}
	if result.Email != "" {
		or = append(or, bson.M{"entities.$.type": goauthlib.EntityTypeEmail, "entities.$.value": result.Email})
	}
	if result.Phone != "" {
		or = append(or, bson.M{"entities.$.type": goauthlib.EntityTypePhone, "entities.$.value": result.Phone})
	}
	return repo.getOneUser(bson.M{"$or": or})
}

func (repo *Repository) CreateForSocial(result *goauthlib.ProviderResult) *goauthlib.User {
	entities := []mongoAuthorizationEntity{{Type: result.Type, Value:result.ID}}
	if result.Email != "" {
		entities = append(entities, mongoAuthorizationEntity{
			Value: result.Email,
			Type:  goauthlib.EntityTypeEmail,
		})
	}
	if result.Phone != "" {
		entities = append(entities, mongoAuthorizationEntity{
			Value: result.Phone,
			Type:  goauthlib.EntityTypePhone,
		})
	}
	mongoUser := mongoUser{
		ID:       primitive.NewObjectID(),
		Entities: entities,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := repo.Client.Database(dbName).Collection(userCollection).InsertOne(ctx, mongoUser)
	if err != nil {
		panic(err)
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) getOneUser(query bson.M) *goauthlib.User {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := repo.Client.Database(dbName).Collection(userCollection).FindOne(ctx,  query)
	if res.Err() != nil {
		panic(res.Err().Error())
	}
	var mongoUser mongoUser
	err := res.Decode(&mongoUser)
	if err != nil {
		panic(err)
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) getOneVerification(query bson.M) *goauthlib.Verification {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := repo.Client.Database(dbName).Collection(verificationCollection).FindOne(ctx,  query)
	if res.Err() != nil {
		panic(res.Err().Error())
	}
	var mongoVerification mongoVerification
	err := res.Decode(&mongoVerification)
	if err != nil {
		panic(err)
	}
	return toDomainVerification(&mongoVerification)
}

func (repo *Repository) GetForEntity(entity goauthlib.AuthorizationEntity) *goauthlib.User {
	return repo.getOneUser(bson.M{"entities.$.type": entity.Type, "entities.$.value": entity.Value})
}

func (repo *Repository) CreateForEntity(entity goauthlib.AuthorizationEntity) *goauthlib.User{
	mongoUser := mongoUser{
		ID:       primitive.NewObjectID(),
		Entities: []mongoAuthorizationEntity{toMongoEntity(entity)},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := repo.Client.Database(dbName).Collection(userCollection).InsertOne(ctx, mongoUser)
	if err != nil{
		panic(err)
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) Save(model *goauthlib.User) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mongoUser := toMongoUser(model)
	_, err := repo.Client.Database(dbName).Collection(userCollection).UpdateOne(ctx, bson.M{"_id": mongoUser.ID}, mongoUser, nil)
	if err != nil {
		panic(err)
	}
}

func (repo *Repository) GetById(id string) *goauthlib.User {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		panic(err)
	}
	return repo.getOneUser(bson.M{"_id": objectID})
}
