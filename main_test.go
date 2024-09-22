package main

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func Test_generateKeys(t *testing.T) {
	keys := generateKeys()
	if len(keys) != 2 {
		t.Fatalf(`generateKeys returned %v keys, expected 2`, len(keys))
	}
}

func Test_getJWKs(t *testing.T) {
	keys := generateKeys()
	jwks := getJWKs(keys)
	spew.Dump(len(jwks.Keys))

	keyCount := len(jwks.Keys)
	if keyCount != 1 {
		t.Fatalf(`getJWKS returned %v keys, expected 1`, keyCount)
	}
}

func Test_generateJWT(t *testing.T) {
	keys := generateKeys()

	_, err := generateJWT(keys, false)
	if err != nil {
		t.Fatalf("error running generateJWT (expired=false): %v", err)
	}

	_, err = generateJWT(keys, true)
	if err != nil {
		t.Fatalf("error running generateJWT (expired=true): %v", err)
	}
}
