package mongo

import (
	"context"
	"github.com/techpro-studio/goauthlib"
	"github.com/techpro-studio/goauthlib/oauth"
	"github.com/techpro-studio/gohttplib/utils"
	"github.com/techpro-studio/gomongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"time"
)

const notFoundDocumentError = "mongo: no documents in result"

type Repository struct {
	Client  *mongo.Client
	service string
}

func (repo *Repository) SoftDeleteUser(ctx context.Context, id bson.ObjectID) error {
	_, err := repo.Client.Database(dbName).Collection(userCollection).UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"deleted": true}})
	return err
}

func (repo *Repository) DeleteVerification(ctx context.Context, id string) {
	objId, err := bson.ObjectIDFromHex(id)
	if err != nil {
		panic(err)
	}
	_, err = repo.Client.Database(dbName).Collection(verificationCollection).DeleteOne(ctx, bson.M{"_id": objId})
	if err != nil {
		panic(err)
	}
}

func NewRepository(client *mongo.Client, service string) *Repository {
	return &Repository{Client: client, service: service}
}

func (repo *Repository) GetVerificationForEntity(ctx context.Context, entity goauthlib.AuthorizationEntity) *goauthlib.Verification {
	return repo.getOneVerification(ctx, bson.M{"destination": entity.Value, "destination_type": entity.Type, "service": repo.service})
}

func (repo *Repository) CreateVerificationForEntity(ctx context.Context, entity goauthlib.AuthorizationEntity, verificationCode string) {
	q := bson.M{"destination": entity.Value, "destination_type": entity.Type}
	u := bson.M{
		"$set": bson.M{
			"destination":      entity.Value,
			"destination_type": entity.Type,
			"timestamp":        time.Now().Unix(),
			"code":             verificationCode,
			"service":          repo.service,
		},
	}
	_, err := repo.Client.Database(dbName).Collection(verificationCollection).UpdateOne(ctx, q, u, options.UpdateOne().SetUpsert(true))
	if err != nil {
		panic(err)
	}
}

func (repo *Repository) GetServiceActionVerification(ctx context.Context, action string) *goauthlib.Verification {
	return repo.getOneVerification(ctx, bson.M{"action": action, "service": repo.service})
}

func (repo *Repository) CreateServiceActionVerification(ctx context.Context, action, verificationCode string) {
	q := bson.M{"removal": repo.service}
	u := bson.M{
		"$set": bson.M{
			"action":    action,
			"timestamp": time.Now().Unix(),
			"code":      verificationCode,
			"service":   repo.service,
		},
	}
	_, err := repo.Client.Database(dbName).Collection(verificationCollection).UpdateOne(ctx, q, u, options.UpdateOne().SetUpsert(true))
	if err != nil {
		panic(err)
	}
}

func (repo *Repository) GetForSocial(ctx context.Context, result *oauth.ProviderResult) *goauthlib.User {
	or := []bson.M{{"entities.type": result.Type, "entities.value": result.ID}}
	if result.Email != "" {
		or = append(or, bson.M{"entities.type": goauthlib.EntityTypeEmail, "entities.value": result.Email})
	}
	if result.Phone != "" {
		or = append(or, bson.M{"entities.type": goauthlib.EntityTypePhone, "entities.value": result.Phone})
	}
	return repo.getOneUser(ctx, bson.M{"$or": or}, false)
}

func (repo *Repository) SaveOAuthData(ctx context.Context, result *oauth.ProviderResult) {
	_, err := repo.Client.Database(dbName).Collection(oauthDataCollection).UpdateOne(ctx, map[string]interface{}{"type": result.Type, "provider_id": result.ID, "service": repo.service}, map[string]interface{}{"$set": map[string]interface{}{"data": result.Raw, "tokens": bson.M{"access": result.Tokens.Access, "refresh": result.Tokens.Refresh}}}, options.UpdateOne().SetUpsert(true))
	if err != nil {
		panic(err)
	}
}

func (repo *Repository) GetTokensFor(ctx context.Context, entity *goauthlib.AuthorizationEntity) (*oauth.Tokens, error) {
	dbResult := repo.Client.Database(dbName).Collection(oauthDataCollection).FindOne(ctx, map[string]interface{}{"type": entity.Type, "provider_id": entity.Value, "service": repo.service})
	var result struct {
		Tokens *oauth.Tokens `bson:"tokens"`
	}
	err := dbResult.Decode(&result)
	if err != nil {
		if err.Error() != notFoundDocumentError {
			return nil, err
		}
		return nil, nil
	}
	if result.Tokens == nil {
		return nil, nil
	}
	return &oauth.Tokens{
		Access:  result.Tokens.Access,
		Refresh: result.Tokens.Refresh,
	}, err
}

func (repo *Repository) UpsertForEntity(ctx context.Context, entity goauthlib.AuthorizationEntity, info map[string]any) (*goauthlib.User, error) {
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var mongoUser mongoUser
	setMap := bson.M{"deleted": false}
	if info != nil && len(info) > 0 {
		setMap["info"] = info
	}
	err := repo.Client.Database(dbName).Collection(userCollection).FindOneAndUpdate(ctx, bson.M{"entities.type": entity.Type, "entities.value": entity.Value}, bson.M{"$set": setMap, "$addToSet": bson.M{"services": repo.service}, "$setOnInsert": bson.M{"entities": bson.A{bson.M{"type": entity.Type, "value": entity.Value}}}}, opts).Decode(&mongoUser)
	if err != nil {
		return nil, err
	}
	return toDomainUser(&mongoUser), nil
}

func (repo *Repository) CreateForSocial(ctx context.Context, result *oauth.ProviderResult) *goauthlib.User {
	entities := []mongoAuthorizationEntity{{Type: result.Type, Value: result.ID}}
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
		ID:       bson.NewObjectID(),
		Entities: entities,
		Services: []string{repo.service},
		Info:     nil,
	}
	_, err := repo.Client.Database(dbName).Collection(userCollection).InsertOne(ctx, mongoUser)
	if err != nil {
		panic(err)
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) getOneUser(ctx context.Context, query bson.M, nullIfNoService bool) *goauthlib.User {
	fullQuery :=
		bson.M{"$and": []bson.M{
			{
				"$or": []bson.M{
					{"deleted": false},
					{"deleted": bson.M{"$exists": false}},
				},
			},
			query,
		},
		}

	res := repo.Client.Database(dbName).Collection(userCollection).FindOne(ctx, fullQuery)
	var mongoUser mongoUser
	err := res.Decode(&mongoUser)
	if err != nil {
		if err.Error() != notFoundDocumentError {
			panic(err)
		}
		return nil
	}
	if !utils.ContainsString(mongoUser.Services, repo.service) && nullIfNoService {
		return nil
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) getOneVerification(ctx context.Context, query bson.M) *goauthlib.Verification {
	res := repo.Client.Database(dbName).Collection(verificationCollection).FindOne(ctx, query)
	if res.Err() != nil {
		return nil
	}
	var mongoVerification mongoVerification
	err := res.Decode(&mongoVerification)
	if err != nil {
		return nil
	}
	return toDomainVerification(&mongoVerification)
}

func (repo *Repository) GetForEntity(ctx context.Context, entity goauthlib.AuthorizationEntity) *goauthlib.User {
	return repo.getOneUser(ctx, bson.M{"entities.type": entity.Type, "entities.value": entity.Value}, false)
}

func (repo *Repository) CreateForEntity(ctx context.Context, entity goauthlib.AuthorizationEntity) *goauthlib.User {
	mongoUser := mongoUser{
		ID:       bson.NewObjectID(),
		Entities: []mongoAuthorizationEntity{toMongoEntity(entity)},
		Services: []string{repo.service},
		Info:     map[string]any{},
		Deleted:  false,
	}
	_, err := repo.Client.Database(dbName).Collection(userCollection).InsertOne(ctx, mongoUser)
	if err != nil {
		panic(err)
	}
	return toDomainUser(&mongoUser)
}

func (repo *Repository) RemoveService(ctx context.Context, id string, softDeleteIfNoServices bool, callback func(ctx context.Context, userId string) error) {
	_, err := gomongo.InTransactionSession[gomongo.Void](ctx, repo.Client, func(sc context.Context) (gomongo.Void, error) {
		objId := *gomongo.StrToObjId(&id)
		_, err := repo.Client.
			Database(dbName).
			Collection(userCollection).
			UpdateOne(sc, bson.M{"_id": objId}, bson.M{"$pull": bson.M{"services": repo.service}}, nil)
		if err != nil {
			return gomongo.Void{}, err
		}
		if softDeleteIfNoServices {
			var mongoUsr mongoUser
			err := repo.Client.Database(dbName).
				Collection(userCollection).FindOne(ctx, bson.M{"_id": objId}).Decode(&mongoUsr)

			if err != nil {
				return gomongo.Void{}, err
			}

			if len(mongoUsr.Services) == 1 && mongoUsr.Services[0] == repo.service {
				// IT will delete. transaction has not been commited yet.
				err := repo.SoftDeleteUser(ctx, mongoUsr.ID)
				if err != nil {
					return gomongo.Void{}, err
				}
			}
		}
		err = callback(sc, id)
		if err != nil {
			return gomongo.Void{}, err
		}
		return gomongo.Void{}, nil
	})

	if err != nil {
		panic(err)
	}
}

func (repo *Repository) EnsureService(ctx context.Context, id string) bool {
	return repo.ensureService(ctx, *gomongo.StrToObjId(&id))
}

func (repo *Repository) ensureService(ctx context.Context, userId bson.ObjectID) bool {
	var user mongoUser
	err := repo.Client.
		Database(dbName).
		Collection(userCollection).FindOne(ctx, bson.M{"_id": userId}).Decode(&user)
	if err != nil {
		panic(err)
	}
	if user.Deleted {
		panic("User already deleted")
	}
	hasService := utils.ContainsString(user.Services, repo.service)
	if hasService {
		return false
	}
	_, err = repo.Client.
		Database(dbName).
		Collection(userCollection).
		UpdateOne(ctx, bson.M{"_id": userId}, bson.M{"$addToSet": bson.M{"services": repo.service}}, nil)
	if err != nil {
		panic(err)
	}
	return true
}

func (repo *Repository) Save(ctx context.Context, model *goauthlib.User) {
	mongoUser := toMongoUser(model)
	_, err := repo.Client.
		Database(dbName).
		Collection(userCollection).
		UpdateOne(ctx, bson.M{"_id": mongoUser.ID}, bson.M{"$set": bson.M{"entities": mongoUser.Entities, "info": mongoUser.Info}}, nil)
	if err != nil {
		panic(err)
	}
}

func (repo *Repository) GetById(ctx context.Context, id string) *goauthlib.User {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		panic(err)
	}
	return repo.getOneUser(ctx, bson.M{"_id": objectID}, true)
}
