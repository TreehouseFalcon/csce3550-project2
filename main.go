package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"gopkg.in/square/go-jose.v2"
	_ "modernc.org/sqlite" // Load sqlite driver
)

const PORT uint32 = 8080

type KeyPair struct {
	KID        string
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
	ExpireAt   int64
}

var db *sql.DB

func readKeys(db *sql.DB, includeExpired bool) jose.JSONWebKeySet {
	rows, readAllErr := db.Query("SELECT * FROM keys;")
	if readAllErr != nil {
		log.Fatal(readAllErr)
	}

	// Parse resulting rows //
	var keys []jose.JSONWebKey
	for rows.Next() {
		var kid string
		var keyPEM string
		var exp int64

		readErr := rows.Scan(&kid, &keyPEM, &exp)
		if readErr != nil {
			log.Fatal(readErr)
		}
		if !includeExpired && exp <= time.Now().Unix() {
			continue
		}

		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil {
			log.Fatal("failed to parse PEM block")
		}

		privateKey, privateKeyErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if privateKeyErr != nil {
			log.Fatal(privateKeyErr)
		}

		keys = append(keys, jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}

	// Check for errors iterating over rows //
	err := rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	keySet := jose.JSONWebKeySet{
		Keys: keys,
	}
	return keySet
}

func generateJWT(shouldBeExpired bool) (string, error) {
	keys := readKeys(db, true).Keys

	// Select between expired key and active key //
	var expireAt int64
	var kid string
	var privateKey *rsa.PrivateKey
	if shouldBeExpired {
		// Choose expired key //
		expireAt = time.Now().Add(time.Hour * -24).Unix()
		kid = keys[1].KeyID
		privateKey = keys[1].Key.(*rsa.PrivateKey)
	} else {
		// Choose active key //
		expireAt = time.Now().Add(time.Hour * 24).Unix()
		kid = keys[0].KeyID
		privateKey = keys[0].Key.(*rsa.PrivateKey)
	}

	// Generate JWT //
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": expireAt,
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
	if request.Method != http.MethodPost {
		http.Error(writer, "", http.StatusMethodNotAllowed)
	}
	jwtString, jwtErr := generateJWT(request.URL.Query().Get("expired") != "")
	if jwtErr == nil {
		writer.Header().Set("Content-Type", "application/json")
		encodeErr := json.NewEncoder(writer).Encode(map[string]string{"token": jwtString}) //nolint:golint,errcheck
		if encodeErr != nil {
			fmt.Printf("failed to encode response: %v", encodeErr)
		}
	} else {
		http.Error(writer, jwtErr.Error(), http.StatusInternalServerError)
	}
}

// GET /.well-known/jwks.json
func getJWKSJson(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "", http.StatusMethodNotAllowed)
	}

	// Send response //
	writer.Header().Set("Content-Type", "application/json")
	keys := readKeys(db, false)
	json.NewEncoder(writer).Encode(keys) //nolint:golint,errcheck
}

func initDb() (*sql.DB, error) {
	db, dbErr := sql.Open("sqlite", "./totally_not_my_privateKeys.db")
	if dbErr != nil {
		log.Fatal(dbErr)
	}

	CREATE_TABLE_QUERY := `
	CREATE TABLE IF NOT EXISTS keys(
    kid TEXT PRIMARY KEY,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
	);
	`

	_, createSchemaErr := db.Exec(CREATE_TABLE_QUERY)
	if createSchemaErr != nil {
		log.Fatal(createSchemaErr)
	}

	return db, nil
}

func initKeys(db *sql.DB) {
	// Check for existing keys //
	var keyCount int
	countErr := db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?;", time.Now().Unix()).Scan(&keyCount)
	if countErr != nil {
		log.Fatal(countErr)
	}
	if keyCount > 0 {
		fmt.Printf("Skipping key generation, non-expired already exists\n")
		return
	}

	// Generate active key //
	fmt.Printf("Clearing existing keys\n")
	_, clearErr := db.Exec("DELETE FROM keys;")
	if clearErr != nil {
		log.Fatal(clearErr)
	}

	fmt.Printf("Generating keys\n")
	var activeKid, expiredKid string
	var activePublicKey, expiredPublicKey *rsa.PublicKey
	var activePrivateKey, expiredPrivateKey *rsa.PrivateKey

	{
		var keygenErr error
		activePrivateKey, keygenErr = rsa.GenerateKey(rand.Reader, 2048)
		if keygenErr != nil {
			panic(keygenErr)
		}
		activeKid = "1001"
		activePublicKey = &activePrivateKey.PublicKey
	}
	// Generate expired key //
	{
		var keygenErr error
		expiredPrivateKey, keygenErr = rsa.GenerateKey(rand.Reader, 2048)
		if keygenErr != nil {
			panic(keygenErr)
		}
		expiredKid = "1002"
		expiredPublicKey = &expiredPrivateKey.PublicKey
	}

	keys := []KeyPair{
		{
			KID:        activeKid,
			PublicKey:  activePublicKey,
			PrivateKey: activePrivateKey,
			ExpireAt:   time.Now().Unix() + 3600, // expire in an hour
		},
		{
			KID:        expiredKid,
			PublicKey:  expiredPublicKey,
			PrivateKey: expiredPrivateKey,
			ExpireAt:   time.Now().Unix() - 3600, // expire an hour ago
		},
	}

	for _, key := range keys {
		privateKeyDER := x509.MarshalPKCS1PrivateKey(key.PrivateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyDER,
		})

		_, insertErr := db.Exec("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?) ON CONFLICT(kid) DO UPDATE SET key=excluded.key, exp=excluded.exp;", key.KID, privateKeyPEM, key.ExpireAt)
		if insertErr != nil {
			log.Fatal(insertErr)
		}
	}

}

func main() {
	db, _ = initDb()
	initKeys(db)
	http.HandleFunc("/.well-known/jwks.json", getJWKSJson)
	http.HandleFunc("/auth", postAuth)
	http.ListenAndServe(fmt.Sprintf(":%v", PORT), nil) //nolint:golint,errcheck
}
