package goauthlib

import (
	"crypto/ed25519"
	"go.mongodb.org/mongo-driver/v2/bson"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateTokenAndValidate(t *testing.T) {
	user := User{ID: bson.NewObjectID().Hex()}
	blinder := "test-blinder"
	signingKey := []byte("my-secret-key")

	token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodHS256, signingKey)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := GetClaimsFromToken(token, jwt.SigningMethodHS256, signingKey)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if claims["user"].(map[string]any)["id"] != user.ID {
		t.Errorf("user ID mismatch: got %v, want %v", claims["user"].(map[string]any)["id"], user.ID)
	}
	if claims["hash"] == "" {
		t.Error("hash claim is empty")
	}
}

func TestGenerateTokenHashConsistency(t *testing.T) {
	user := User{ID: bson.NewObjectID().Hex()}
	blinder := "blinder1"

	hash1 := GenerateTokenHash(user, blinder)
	hash2 := GenerateTokenHash(user, blinder)

	if hash1 != hash2 {
		t.Errorf("hash mismatch: %s != %s", hash1, hash2)
	}
}

func TestSafeExtractUserIdFromHeader(t *testing.T) {
	user := User{ID: bson.NewObjectID().Hex()}
	blinder := "blinder-header"
	signingKey := []byte("header-secret")

	token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodHS256, signingKey)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	header := http.Header{}
	header.Set("Authorization", "JWT "+token)

	userId, err := SafeExtractUserIdFromHeader(header, jwt.SigningMethodHS256, signingKey)
	if err != nil {
		t.Fatalf("SafeExtractUserIdFromHeader failed: %v", err)
	}

	if userId != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, userId)
	}
}

func TestGetValidUserFromToken(t *testing.T) {
	user := User{ID: bson.NewObjectID().Hex()}
	blinder := "blinder-valid"
	signingKey := []byte("key-valid")
	config := Config{
		signingMethod: jwt.SigningMethodHS256,
		signingKey:    signingKey,
		blinder:       blinder,
	}

	token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodHS256, []byte(signingKey))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	validUser, err := GetValidUserFromToken(token, config)
	if err != nil {
		t.Fatalf("GetValidUserFromToken failed: %v", err)
	}

	if validUser.ID != user.ID {
		t.Errorf("expected ID %s, got %s", user.ID, validUser.ID)
	}
}

func TestExpiredToken(t *testing.T) {
	user := User{ID: "abcdef1234567890abcdef1234567890"}
	blinder := "expired-blinder"
	signingKey := []byte("expired-secret")

	claims := struct {
		Hash string `json:"hash"`
		User User
		jwt.RegisteredClaims
	}{
		Hash: GenerateTokenHash(user, blinder),
		User: user,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}

	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, _ := tokenObj.SignedString(signingKey)

	_, err := GetClaimsFromToken(token, jwt.SigningMethodHS256, signingKey)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestInvalidAuthorizationHeader(t *testing.T) {
	header := http.Header{}
	_, err := SafeExtractUserIdFromHeader(header, jwt.SigningMethodHS256, []byte("key"))
	if err == nil {
		t.Error("expected error for missing header")
	}

	header.Set("Authorization", "Bearer xyz")
	_, err = SafeExtractUserIdFromHeader(header, jwt.SigningMethodHS256, []byte("key"))
	if err == nil {
		t.Error("expected error for invalid header format")
	}
}

func TestGenerateTokenAndValidateEd25519(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key pair: %v", err)
	}

	user := User{ID: bson.NewObjectID().Hex()}
	blinder := "ed25519-blinder"

	// Use jwt.SigningMethodEdDSA for Ed25519
	token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodEdDSA, privateKey)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 token: %v", err)
	}

	claims, err := GetClaimsFromToken(token, jwt.SigningMethodEdDSA, publicKey)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 token: %v", err)
	}

	if claims["user"].(map[string]any)["id"] != user.ID {
		t.Errorf("user ID mismatch: got %v, want %v", claims["user"].(map[string]any)["id"], user.ID)
	}
	if claims["hash"] == "" {
		t.Error("hash claim is empty in Ed25519 token")
	}

	// Test GetValidUserFromToken with Ed25519 keys
	config := Config{
		signingMethod: jwt.SigningMethodEdDSA,
		signingKey:    publicKey,
		blinder:       blinder,
	}

	validUser, err := GetValidUserFromToken(token, config)
	if err != nil {
		t.Fatalf("GetValidUserFromToken failed for Ed25519 token: %v", err)
	}

	if validUser.ID != user.ID {
		t.Errorf("expected ID %s, got %s for Ed25519 token", user.ID, validUser.ID)
	}
}

func TestCornerCases(t *testing.T) {
	// Setup keys and user
	hsKey := []byte("corner-case-key")
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keys: %v", err)
	}

	emptyUser := User{ID: ""}
	normalUser := User{ID: bson.NewObjectID().Hex()}

	blinders := []string{
		"",
		"normal-blinder",
		strings.Repeat("a", 1000),
		"!@#$%^&*()_+-=[]{}|;':,.<>/?",
	}

	signingMethods := []jwt.SigningMethod{
		jwt.SigningMethodHS256,
		jwt.SigningMethodEdDSA,
	}

	for _, sm := range signingMethods {
		for _, blinder := range blinders {
			// Select key based on signing method
			var privKey any
			var pubKey any
			if sm == jwt.SigningMethodHS256 {
				privKey = hsKey
				pubKey = hsKey
			} else {
				privKey = edPriv
				pubKey = edPub
			}

			// Test empty user ID token generation and validation
			token, err := GenerateTokenFromModel(emptyUser, blinder, sm, privKey)
			if err != nil {
				t.Errorf("failed to generate token with empty user ID, method %v, blinder '%s': %v", sm.Alg(), blinder, err)
				continue
			}
			claims, err := GetClaimsFromToken(token, sm, pubKey)
			if err != nil {
				t.Errorf("failed to parse token with empty user ID, method %v, blinder '%s': %v", sm.Alg(), blinder, err)
				continue
			}
			if claims["user"].(map[string]any)["id"] != "" {
				t.Errorf("expected empty user ID, got %v, method %v, blinder '%s'", claims["user"].(map[string]any)["id"], sm.Alg(), blinder)
			}

			// Test normal user with blinder edge cases
			token, err = GenerateTokenFromModel(normalUser, blinder, sm, privKey)
			if err != nil {
				t.Errorf("failed to generate token normal user, method %v, blinder '%s': %v", sm.Alg(), blinder, err)
				continue
			}

			// Tamper with token to create invalid token scenarios
			invalidTokens := []string{
				"",                      // empty token
				"abc.def",               // incomplete token parts
				token + "tampered",      // token with extra data
				token[:len(token)-1],    // truncated token
				"eyJhbGciOiJIUzI1NiJ9.", // header only
			}

			for _, invalidToken := range invalidTokens {
				_, err := GetClaimsFromToken(invalidToken, sm, pubKey)
				if err == nil {
					t.Errorf("expected error for invalid token '%s', method %v", invalidToken, sm.Alg())
				}
			}

			// Generate valid token and tamper with hash claim to test hash mismatch
			token, err = GenerateTokenFromModel(normalUser, blinder, sm, privKey)
			if err != nil {
				t.Errorf("failed to generate token for hash mismatch test, method %v, blinder '%s': %v", sm.Alg(), blinder, err)
				continue
			}

			claims, err = GetClaimsFromToken(token, sm, pubKey)
			if err != nil {
				t.Errorf("failed to parse token for hash mismatch test, method %v, blinder '%s': %v", sm.Alg(), blinder, err)
				continue
			}

			// Modify hash claim
			claims["hash"] = "invalidhash"

			// Re-encode token with modified claims (only works for HS256 here)
			if sm == jwt.SigningMethodHS256 {
				mapClaims := jwt.MapClaims(claims)
				newToken := jwt.NewWithClaims(sm, mapClaims)
				signedToken, err := newToken.SignedString(privKey)
				if err != nil {
					t.Errorf("failed to sign modified token for hash mismatch test: %v", err)
					continue
				}

				// Validate user from modified token
				config := Config{signingMethod: sm, signingKey: pubKey, blinder: blinder}
				_, err = GetValidUserFromToken(signedToken, config)
				if err == nil {
					t.Errorf("expected error due to hash mismatch for method %v, blinder '%s'", sm.Alg(), blinder)
				}
			}

			// Test wrong signing method for token validation
			var wrongMethod jwt.SigningMethod = jwt.SigningMethodHS256
			if sm == jwt.SigningMethodHS256 {
				wrongMethod = jwt.SigningMethodEdDSA
			}
			_, err = GetClaimsFromToken(token, wrongMethod, pubKey)
			if err == nil {
				t.Errorf("expected error for wrong signing method %v validating token signed with %v", wrongMethod.Alg(), sm.Alg())
			}

			// Test malformed Authorization headers
			header := http.Header{}
			header.Set("Authorization", "JWT") // no token
			_, err = SafeExtractUserIdFromHeader(header, sm, pubKey)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (no token), method %v", sm.Alg())
			}

			header.Set("Authorization", "JWT"+token) // no space
			_, err = SafeExtractUserIdFromHeader(header, sm, pubKey)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (no space), method %v", sm.Alg())
			}

			header.Set("Authorization", "Bearer "+token) // wrong scheme
			_, err = SafeExtractUserIdFromHeader(header, sm, pubKey)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (wrong scheme), method %v", sm.Alg())
			}

			// Test expired token
			expiredClaims := struct {
				Hash string `json:"hash"`
				User User
				jwt.RegisteredClaims
			}{
				Hash: GenerateTokenHash(normalUser, blinder),
				User: normalUser,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "auth",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			}
			expTokenObj := jwt.NewWithClaims(sm, expiredClaims)
			expToken, err := expTokenObj.SignedString(privKey)
			if err != nil {
				t.Errorf("failed to sign expired token, method %v: %v", sm.Alg(), err)
				continue
			}
			_, err = GetClaimsFromToken(expToken, sm, pubKey)
			if err == nil {
				t.Errorf("expected error for expired token, method %v", sm.Alg())
			}

			// Test not-before token (nbf in future)
			nbfClaims := struct {
				Hash string `json:"hash"`
				User User
				jwt.RegisteredClaims
			}{
				Hash: GenerateTokenHash(normalUser, blinder),
				User: normalUser,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "auth",
					NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute)),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}
			nbfTokenObj := jwt.NewWithClaims(sm, nbfClaims)
			nbfToken, err := nbfTokenObj.SignedString(privKey)
			if err != nil {
				t.Errorf("failed to sign nbf token, method %v: %v", sm.Alg(), err)
				continue
			}
			_, err = GetClaimsFromToken(nbfToken, sm, pubKey)
			if err == nil {
				t.Errorf("expected error for not-before token, method %v", sm.Alg())
			}
		}
	}

	// Concurrency test: generate and validate tokens concurrently for both HS256 and Ed25519
	var wg sync.WaitGroup
	concurrency := 10
	for i := 0; i < concurrency; i++ {
		wg.Add(2)

		go func(i int) {
			defer wg.Done()
			user := User{ID: bson.NewObjectID().Hex()}
			blinder := "concurrent-blinder"
			token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodHS256, hsKey)
			if err != nil {
				t.Errorf("concurrent HS256 token generation failed: %v", err)
				return
			}
			claims, err := GetClaimsFromToken(token, jwt.SigningMethodHS256, hsKey)
			if err != nil {
				t.Errorf("concurrent HS256 token validation failed: %v", err)
				return
			}
			if claims["user"].(map[string]any)["id"] != user.ID {
				t.Errorf("concurrent HS256 user ID mismatch: got %v, want %v", claims["user"].(map[string]any)["id"], user.ID)
			}
		}(i)

		go func(i int) {
			defer wg.Done()
			user := User{ID: bson.NewObjectID().Hex()}
			blinder := "concurrent-blinder"
			token, err := GenerateTokenFromModel(user, blinder, jwt.SigningMethodEdDSA, edPriv)
			if err != nil {
				t.Errorf("concurrent Ed25519 token generation failed: %v", err)
				return
			}
			claims, err := GetClaimsFromToken(token, jwt.SigningMethodEdDSA, edPub)
			if err != nil {
				t.Errorf("concurrent Ed25519 token validation failed: %v", err)
				return
			}
			if claims["user"].(map[string]any)["id"] != user.ID {
				t.Errorf("concurrent Ed25519 user ID mismatch: got %v, want %v", claims["user"].(map[string]any)["id"], user.ID)
			}
		}(i)
	}
	wg.Wait()
}
