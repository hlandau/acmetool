package acmeapi

import (
	"crypto/rand"
	"crypto/rsa"
	"golang.org/x/net/context"
	"testing"
)

func TestAPI(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("couldn't generate key: %v", err)
	}

	TestingAllowHTTP = true

	cl := Client{
		DirectoryURL: "http://127.0.0.1:4000/directory",
	}
	cl.AccountInfo.AccountKey = pk
	cl.AccountInfo.AgreementURIs = map[string]struct{}{
		"http://127.0.0.1:4001/terms/v1": {},
	}
	cl.AccountInfo.ContactURIs = []string{
		"mailto:nobody@localhost",
	}

	err = cl.UpsertRegistration(context.TODO())
	if err != nil {
		t.Fatalf("couldn't upsert registration: %v", err)
	}

	auth, err := cl.NewAuthorization("dom1.acmetool-test.devever.net", context.TODO())
	if err != nil {
		t.Fatalf("couldn't create authorization: %v", err)
	}

	err = cl.LoadAuthorization(auth, context.TODO())
	if err != nil {
		t.Fatalf("couldn't load authorization")
	}

	err = cl.LoadChallenge(auth.Challenges[0], context.TODO())
	if err != nil {
		t.Fatalf("couldn't load challenge")
	}

	// TODO
	//cl.RespondToChallenge
	//cl.WaitLoadChallenge
	//cl.RequestCertificate
}

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
