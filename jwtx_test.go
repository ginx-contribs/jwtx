package jwtx

import (
	"github.com/golang-jwt/jwt/v5"
	"testing"
)

func TestToken(t *testing.T) {
	key := []byte(("my-key"))
	token, err := Issue(key, jwt.SigningMethodHS256)
	if err != nil {
		t.Fatal(err)
	}

	if token.SignedString == "" {
		t.Fatal("unexpected empty token string")
	}

	_, err = Verify(token.SignedString, key, jwt.SigningMethodHS256)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTokenWithClaims(t *testing.T) {

	key := []byte(("my-key"))
	token, err := IssueWithClaims(key, jwt.SigningMethodHS256, &jwt.RegisteredClaims{
		Issuer: "jwtx",
	})
	if err != nil {
		t.Fatal(err)
	}

	if token.SignedString == "" {
		t.Fatal("unexpected empty token string")
	}

	verfiedToken, err := VerifyWithClaims(token.SignedString, key, jwt.SigningMethodHS256, &jwt.RegisteredClaims{})
	if err != nil {
		t.Fatal(err)
	}

	orignalIssuer, err := token.Token.Claims.GetIssuer()
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := verfiedToken.Claims.GetIssuer()
	if err != nil {
		t.Fatal(err)
	}

	if issuer != orignalIssuer {
		t.Fatal("unexpected issuer")
	}

	t.Log(orignalIssuer, issuer)
}
