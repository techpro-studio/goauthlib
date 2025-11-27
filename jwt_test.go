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

	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      []byte("my-secret-key"),
		verificationKey: []byte("my-secret-key"),
		blinder:         "test-blinder",
	}

	token, err := jwtCfg.GenerateTokenFromModel(user)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := jwtCfg.GetClaimsFromToken(token)
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
	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      []byte("my-secret-key"),
		verificationKey: []byte("my-secret-key"),
		blinder:         "test-blinder",
	}

	token, err := jwtCfg.GenerateTokenFromModel(user)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	header := http.Header{}
	header.Set("Authorization", "JWT "+token)

	userId, err := jwtCfg.SafeExtractUserIdFromHeader(header)
	if err != nil {
		t.Fatalf("SafeExtractUserIdFromHeader failed: %v", err)
	}

	if userId != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, userId)
	}
}

func TestGetValidUserFromToken(t *testing.T) {
	user := User{ID: bson.NewObjectID().Hex()}

	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      []byte("my-secret-key"),
		verificationKey: []byte("my-secret-key"),
		blinder:         "test-blinder",
	}

	token, err := jwtCfg.GenerateTokenFromModel(user)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	validUser, err := jwtCfg.GetValidUserFromToken(token)
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

	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      signingKey,
		verificationKey: signingKey,
		blinder:         blinder,
	}

	_, err := jwtCfg.GetClaimsFromToken(token)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestInvalidAuthorizationHeader(t *testing.T) {
	header := http.Header{}
	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      []byte("key"),
		verificationKey: []byte("key"),
		blinder:         "some",
	}
	_, err := jwtCfg.SafeExtractUserIdFromHeader(header)
	if err == nil {
		t.Error("expected error for missing header")
	}

	header.Set("Authorization", "Bearer xyz")
	_, err = jwtCfg.SafeExtractUserIdFromHeader(header)
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
	jwtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodEdDSA,
		signingKey:      privateKey,
		verificationKey: publicKey,
		blinder:         "test-blinder",
	}

	// Use jwt.SigningMethodEdDSA for Ed25519
	token, err := jwtCfg.GenerateTokenFromModel(user)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 token: %v", err)
	}

	claims, err := jwtCfg.GetClaimsFromToken(token)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 token: %v", err)
	}

	if claims["user"].(map[string]any)["id"] != user.ID {
		t.Errorf("user ID mismatch: got %v, want %v", claims["user"].(map[string]any)["id"], user.ID)
	}
	if claims["hash"] == "" {
		t.Error("hash claim is empty in Ed25519 token")
	}

	validUser, err := jwtCfg.GetValidUserFromToken(token)
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

	hmacJWtCfg := JWTConfig{
		signingMethod:   jwt.SigningMethodHS256,
		signingKey:      hsKey,
		verificationKey: hsKey,
	}

	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keys: %v", err)
	}
	edJwtCFG := JWTConfig{
		signingMethod:   jwt.SigningMethodEdDSA,
		signingKey:      edPriv,
		verificationKey: edPub,
	}

	emptyUser := User{ID: ""}
	normalUser := User{ID: bson.NewObjectID().Hex()}

	blinders := []string{
		"",
		"normal-blinder",
		strings.Repeat("a", 1000),
		"!@#$%^&*()_+-=[]{}|;':,.<>/?",
	}

	jwtCfgs := []JWTConfig{
		hmacJWtCfg,
		edJwtCFG,
	}

	for _, jwtCfg := range jwtCfgs {
		for _, blinder := range blinders {
			// Select key based on signing method
			jwtCfg.blinder = blinder

			// Test empty user ID token generation and validation
			token, err := jwtCfg.GenerateTokenFromModel(emptyUser)
			if err != nil {
				t.Errorf("failed to generate token with empty user ID, method %v, blinder '%s': %v", jwtCfg.signingMethod.Alg(), blinder, err)
				continue
			}
			claims, err := jwtCfg.GetClaimsFromToken(token)
			if err != nil {
				t.Errorf("failed to parse token with empty user ID, method %v, blinder '%s': %v", jwtCfg.signingMethod.Alg(), blinder, err)
				continue
			}
			if claims["user"].(map[string]any)["id"] != "" {
				t.Errorf("expected empty user ID, got %v, method %v, blinder '%s'", claims["user"].(map[string]any)["id"], jwtCfg.signingMethod.Alg(), blinder)
			}

			// Test normal user with blinder edge cases
			token, err = jwtCfg.GenerateTokenFromModel(normalUser)
			if err != nil {
				t.Errorf("failed to generate token normal user, method %v, blinder '%s': %v", jwtCfg.signingMethod.Alg(), blinder, err)
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
				_, err := jwtCfg.GetClaimsFromToken(invalidToken)
				if err == nil {
					t.Errorf("expected error for invalid token '%s', method %v", invalidToken, jwtCfg.signingMethod.Alg())
				}
			}

			// Generate valid token and tamper with hash claim to test hash mismatch
			token, err = jwtCfg.GenerateTokenFromModel(normalUser)
			if err != nil {
				t.Errorf("failed to generate token for hash mismatch test, method %v, blinder '%s': %v", jwtCfg.signingMethod.Alg(), blinder, err)
				continue
			}

			claims, err = jwtCfg.GetClaimsFromToken(token)
			if err != nil {
				t.Errorf("failed to parse token for hash mismatch test, method %v, blinder '%s': %v", jwtCfg.signingMethod.Alg(), blinder, err)
				continue
			}

			// Modify hash claim
			claims["hash"] = "invalidhash"

			// Re-encode token with modified claims (only works for HS256 here)
			if jwtCfg.signingMethod == jwt.SigningMethodHS256 {
				mapClaims := jwt.MapClaims(claims)
				newToken := jwt.NewWithClaims(jwtCfg.signingMethod, mapClaims)
				signedToken, err := newToken.SignedString(jwtCfg.signingKey)
				if err != nil {
					t.Errorf("failed to sign modified token for hash mismatch test: %v", err)
					continue
				}

				// Validate user from modified token

				_, err = jwtCfg.GetValidUserFromToken(signedToken)
				if err == nil {
					t.Errorf("expected error due to hash mismatch for method %v, blinder '%s'", jwtCfg.signingMethod.Alg(), blinder)
				}
			}

			// Test wrong signing method for token validation
			var wrongMethod jwt.SigningMethod = jwt.SigningMethodHS256
			if jwtCfg.signingMethod == jwt.SigningMethodHS256 {
				wrongMethod = jwt.SigningMethodEdDSA
			}
			wrongCopy := jwtCfg.Copy()
			wrongCopy.signingMethod = wrongMethod

			_, err = wrongCopy.GetClaimsFromToken(token)
			if err == nil {
				t.Errorf("expected error for wrong signing method %v validating token signed with %v", wrongMethod.Alg(), jwtCfg.signingMethod.Alg())
			}

			// Test malformed Authorization headers
			header := http.Header{}
			header.Set("Authorization", "JWT") // no token
			_, err = jwtCfg.SafeExtractUserIdFromHeader(header)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (no token), method %v", jwtCfg.signingMethod.Alg())
			}

			header.Set("Authorization", "JWT"+token) // no space
			_, err = jwtCfg.SafeExtractUserIdFromHeader(header)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (no space), method %v", jwtCfg.signingMethod.Alg())
			}

			header.Set("Authorization", "Bearer "+token) // wrong scheme
			_, err = jwtCfg.SafeExtractUserIdFromHeader(header)
			if err == nil {
				t.Errorf("expected error for malformed Authorization header (wrong scheme), method %v", jwtCfg.signingMethod.Alg())
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
			expTokenObj := jwt.NewWithClaims(jwtCfg.signingMethod, expiredClaims)
			expToken, err := expTokenObj.SignedString(jwtCfg.signingKey)
			if err != nil {
				t.Errorf("failed to sign expired token, method %v: %v", jwtCfg.signingMethod.Alg(), err)
				continue
			}
			_, err = jwtCfg.GetClaimsFromToken(expToken)
			if err == nil {
				t.Errorf("expected error for expired token, method %v", jwtCfg.signingMethod.Alg())
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
			nbfTokenObj := jwt.NewWithClaims(jwtCfg.signingMethod, nbfClaims)
			nbfToken, err := nbfTokenObj.SignedString(jwtCfg.signingKey)
			if err != nil {
				t.Errorf("failed to sign nbf token, method %v: %v", jwtCfg.signingMethod.Alg(), err)
				continue
			}
			_, err = jwtCfg.GetClaimsFromToken(nbfToken)
			if err == nil {
				t.Errorf("expected error for not-before token, method %v", jwtCfg.signingMethod.Alg())
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

			token, err := hmacJWtCfg.GenerateTokenFromModel(user)
			if err != nil {
				t.Errorf("concurrent HS256 token generation failed: %v", err)
				return
			}
			claims, err := hmacJWtCfg.GetClaimsFromToken(token)
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
			token, err := edJwtCFG.GenerateTokenFromModel(user)
			if err != nil {
				t.Errorf("concurrent Ed25519 token generation failed: %v", err)
				return
			}
			claims, err := edJwtCFG.GetClaimsFromToken(token)
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
