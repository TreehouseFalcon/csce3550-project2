package main

import (
	"testing"
)

func Test_initDb(t *testing.T) {
	db, err := initDb()
	if err != nil {
		t.Fatalf(`initDb threw an error: %v\n`, err)
	}
	defer db.Close()
}

func Test_initKeys(t *testing.T) {
	db, _ = initDb()
	initKeys(db)
	defer db.Close()

	db, _ = initDb()
	db.Exec("DELETE FROM keys;")
	initKeys(db)
	defer db.Close()
}

func Test_readKeys(t *testing.T) {
	db, _ = initDb()
	initKeys(db)
	keys := readKeys(db, true)
	if len(keys.Keys) != 2 {
		t.Fatalf(`readKeys returned %v keys, expected 2`, len(keys.Keys))
	}
	defer db.Close()
}

func Test_generateJWT(t *testing.T) {
	db, _ = initDb()
	initKeys(db)

	_, err := generateJWT(false)
	if err != nil {
		t.Fatalf("error running generateJWT (expired=false): %v", err)
	}

	_, err = generateJWT(true)
	if err != nil {
		t.Fatalf("error running generateJWT (expired=true): %v", err)
	}
}
