package mongo

import (
	"context"
	"github.com/techpro-studio/goauthlib"
	"github.com/techpro-studio/goauthlib/oauth"
	"github.com/techpro-studio/gomongo"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"testing"
)

func GetTestMongoDB(t *testing.T, ctx context.Context) (*mongo.Database, func()) {
	mongoContainer, err := mongodb.Run(ctx, "mongo:8")
	if err != nil {
		t.Error(err)
	}
	uri, err := mongoContainer.ConnectionString(ctx)
	if err != nil {
		t.Error(err)
	}
	mongoClient, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Errorf("Failed to connect, %v", err)
	}
	cleanUp := func() {
		mongoClient.Disconnect(ctx)
	}

	return mongoClient.Database("test_blockchain"), cleanUp
}

const service = "test_service"

func setup(t *testing.T) (*Repository, func()) {
	ctx := context.Background()
	db, cleanup := GetTestMongoDB(t, ctx)
	client := db.Client()

	repo := NewRepository(client, service)
	return repo, cleanup
}

func TestCreateAndGetVerificationForEntity(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()
	entity := goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "test@example.com",
	}

	repo.CreateVerificationForEntity(ctx, entity, "123456")

	v := repo.GetVerificationForEntity(ctx, entity)
	if v == nil {
		t.Fatal("expected verification but got nil")
	}
	if v.Code != "123456" {
		t.Fatalf("unexpected verification code: %s", v.Code)
	}
	if v.Destination != "test@example.com" {
		t.Fatalf("unexpected destination: %s", v.Destination)
	}
}

func TestUpsertForEntityCreatesUser(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()
	entity := goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypePhone,
		Value: "+111",
	}

	user, err := repo.UpsertForEntity(ctx, entity, map[string]any{"name": "John", "surname": "Some"})
	if err != nil {
		t.Fatal(err)
	}

	if user.Entities[0].Value != "+111" {
		t.Fatalf("unexpected entity value: %s", user.Entities[0].Value)
	}
	if user.Info["name"] != "John" {
		t.Fatalf("expected info name=John got: %+v", user.Info)
	}

	// Upsert again – should update info
	user2, err := repo.UpsertForEntity(ctx, entity, map[string]any{"name": "Updated"})
	if err != nil {
		t.Fatal(err)
	}

	if user2.Info["name"] != "Updated" {
		t.Fatalf("expected updated name, got: %+v", user2.Info)
	}

	if user2.Info["surname"] != "Some" {
		t.Fatalf("expected updated name, got: %+v", user2.Info)
	}
}

func TestCreateForEntity(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()
	entity := goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "a@b.com",
	}

	u := repo.CreateForEntity(ctx, entity)
	if u == nil {
		t.Fatal("expected user but got nil")
	}

	got := repo.GetForEntity(ctx, entity)
	if got == nil {
		t.Fatal("expected user from GetForEntity")
	}

	if got.Entities[0].Value != "a@b.com" {
		t.Fatalf("unexpected entity: %+v", got.Entities)
	}
}

func TestGetForSocial(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()

	result := &oauth.ProviderResult{
		ID:    "social123",
		Type:  "github",
		Email: "git@test.com",
	}

	_ = repo.CreateForSocial(ctx, result)

	user := repo.GetForSocial(ctx, result)
	if user == nil {
		t.Fatal("expected social user but got nil")
	}
}

func TestSoftDeleteUser(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()
	entity := goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "delete@test.com",
	}

	user := repo.CreateForEntity(ctx, entity)

	userId, err := bson.ObjectIDFromHex(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = repo.SoftDeleteUser(ctx, userId)
	if err != nil {
		t.Fatal(err)
	}

	deleted := repo.GetForEntity(ctx, entity)
	if deleted != nil {
		t.Fatal("expected deleted user to not be returned")
	}
}

func TestSaveAndGetTokens(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()

	a := goauthlib.AuthorizationEntity{
		Type:  "google",
		Value: "9999",
	}

	raw := map[string]any{"profile": "xyz"}

	repo.SaveOAuthData(ctx, &oauth.ProviderResult{
		ID:     a.Value,
		Type:   a.Type,
		Raw:    raw,
		Tokens: oauth.Tokens{Access: "acc", Refresh: "ref"},
	})

	tokens, err := repo.GetTokensFor(ctx, &a)
	if err != nil {
		t.Fatal(err)
	}
	if tokens == nil {
		t.Fatal("expected tokens but got nil")
	}

	if tokens.Access != "acc" || tokens.Refresh != "ref" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestEnsureService(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()
	entity := goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "ens@test.com",
	}

	user := repo.CreateForEntity(ctx, entity)

	// ensure service exists (already present)
	added := repo.EnsureService(ctx, user.ID)
	if added {
		t.Fatal("expected false—service already exists")
	}

	// manually remove service to test re-add
	repo.Client.Database(dbName).
		Collection(userCollection).
		UpdateOne(ctx, bson.M{"_id": gomongo.StrToObjId(&user.ID)}, bson.M{"$set": bson.M{"services": []string{}}})

	added = repo.EnsureService(ctx, user.ID)
	if !added {
		t.Fatal("expected service to be added")
	}
}

func TestGetByIdList(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	ctx := context.Background()

	user := repo.CreateForEntity(ctx, goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "ens@test.com",
	})

	user2 := repo.CreateForEntity(ctx, goauthlib.AuthorizationEntity{
		Type:  goauthlib.EntityTypeEmail,
		Value: "ens@test2.com",
	})

	// ensure service exists (already present)
	added := repo.EnsureService(ctx, user.ID)
	if added {
		t.Fatal("expected false—service already exists")
	}

	// manually remove service to test re-add
	users := repo.GetByIdList(ctx, []string{user.ID, user2.ID})

	if len(users) != 2 {
		t.Fatal("expected 2 users")
	}

	if users[0].ID != user.ID {
		t.Fatal("expected user to have ID")
	}
	if users[1].ID != user2.ID {
		t.Fatal("expected user to have ID")
	}
}
