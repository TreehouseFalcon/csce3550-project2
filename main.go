package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
)

const PORT uint32 = 8080

type KeyPair struct {
	KID        string
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// Store key info globally //
var (
	savedKeys []KeyPair
)

func generateKeys() []KeyPair {
	// Generate active key //
	var activeKid, expiredKid string
	var activePublicKey, expiredPublicKey *rsa.PublicKey
	var activePrivateKey, expiredPrivateKey *rsa.PrivateKey

	{
		var keygenErr error
		activePrivateKey, keygenErr = rsa.GenerateKey(rand.Reader, 2048)
		if keygenErr != nil {
			panic(keygenErr)
		}
		activeKid = uuid.New().String()
		activePublicKey = &activePrivateKey.PublicKey
	}
	// Generate expired key //
	{
		var keygenErr error
		expiredPrivateKey, keygenErr = rsa.GenerateKey(rand.Reader, 2048)
		if keygenErr != nil {
			panic(keygenErr)
		}
		expiredKid = uuid.New().String()
		expiredPublicKey = &expiredPrivateKey.PublicKey
	}

	return []KeyPair{
		{
			KID:        activeKid,
			PublicKey:  activePublicKey,
			PrivateKey: activePrivateKey,
		},
		{
			KID:        expiredKid,
			PublicKey:  expiredPublicKey,
			PrivateKey: expiredPrivateKey,
		},
	}
}

func resetKeys() {
	savedKeys = nil
}

func getJWKs(keys []KeyPair) jose.JSONWebKeySet {
	var jwks []jose.JSONWebKey
	for _, key := range keys {
		jwk := jose.JSONWebKey{
			Key:       key.PublicKey,
			KeyID:     key.KID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}
		jwks = append(jwks, jwk)
	}

	keySet := jose.JSONWebKeySet{
		Keys: jwks,
	}

	return keySet
}

func generateJWT(keys []KeyPair, shouldBeExpired bool) (string, error) {
	// Select between expired key and active key //
	var expireAt int64
	var kid string
	var privateKey *rsa.PrivateKey
	if shouldBeExpired {
		// Choose expired key //
		expireAt = time.Now().Add(time.Hour * -24).Unix()
		kid = keys[1].KID
		privateKey = keys[1].PrivateKey
	} else {
		// Choose active key //
		expireAt = time.Now().Add(time.Hour * 24).Unix()
		kid = keys[0].KID
		privateKey = keys[0].PrivateKey
	}

	// Generate JWT //
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  expireAt,
	})

	// Send kid with token //
	token.Header["kid"] = kid

	// Sign token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// POST /auth
func postAuth(writer http.ResponseWriter, request *http.Request) {
	// Only allow POST //
	if request.Method != http.MethodPost {
		http.Error(writer, "", http.StatusMethodNotAllowed)
		return
	}

	jwtString, jwtErr := generateJWT(savedKeys, request.URL.Query().Get("expired") != "")
	if jwtErr == nil {
		// Send response //
		writer.Header().Set("Content-Type", "application/json")

		encodeErr := json.NewEncoder(writer).Encode(map[string]string{"token": jwtString})
		if encodeErr != nil {
			fmt.Printf("failed to encode response: %v", encodeErr)
		}
	} else {
		http.Error(writer, jwtErr.Error(), http.StatusInternalServerError)
	}
}

// GET /.well-known/jwks.json
func getJWKS(writer http.ResponseWriter, request *http.Request) {
	// Only allow GET //
	if request.Method != http.MethodGet {
		http.Error(writer, "", http.StatusMethodNotAllowed)
		return
	}

	// Send response //
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Status", "200 OK")
	encodeErr := json.NewEncoder(writer).Encode(getJWKs(savedKeys))
	if encodeErr != nil {
		fmt.Printf("failed to encode response: %v", encodeErr)
	}
}

func main() {
	fmt.Printf("Creating RSA key pairs...\n")
	savedKeys = generateKeys()
	fmt.Printf("Key pairs created!\n")

	// Establish routes //
	http.HandleFunc("/auth", postAuth)
	http.HandleFunc("/.well-known/jwks.json", getJWKS)

	// Serve web server //
	serveErr := http.ListenAndServe(fmt.Sprintf(":%v", PORT), nil)
	if errors.Is(serveErr, http.ErrServerClosed) {
		fmt.Printf("Error serving on port %v: %v\n", PORT, serveErr)
		os.Exit(-1)
	}
}
