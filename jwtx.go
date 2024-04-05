package jwtx

import (
	"github.com/golang-jwt/jwt/v5"
)

// Token represents a JSON Web Token.
type Token struct {
	Token        *jwt.Token
	Claims       jwt.Claims
	SignedString string
}

// Issue issues a new token with the give method
func Issue(key []byte, method jwt.SigningMethod, opts ...jwt.TokenOption) (*Token, error) {
	token := new(Token)
	newJwt := jwt.New(method, opts...)
	token.Token = newJwt
	signedString, err := newJwt.SignedString(key)
	if err != nil {
		return nil, err
	}
	token.SignedString = signedString
	return token, nil
}

// IssueWithClaims issues a new jwt token with claims
func IssueWithClaims(key []byte, method jwt.SigningMethod, claims jwt.Claims, opts ...jwt.TokenOption) (*Token, error) {
	token := new(Token)
	newJwt := jwt.NewWithClaims(method, claims, opts...)
	token.Token = newJwt
	// singed with key
	signedStr, err := newJwt.SignedString(key)
	if err != nil {
		return nil, err
	}

	token.SignedString = signedStr
	token.Claims = newJwt.Claims

	return token, nil
}

func keyFn(key []byte) func(token *jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) {
		return key, nil
	}
}

// Verify verify a jwt token string.
// Regardless of the result, it will return a *jwt.Token for Token.
func Verify(signedString string, key []byte, method jwt.SigningMethod, options ...jwt.ParserOption) (*Token, error) {
	token := new(Token)
	// check method defaults
	options = append(options, jwt.WithValidMethods([]string{method.Alg()}))
	// parsed token
	parsedJwt, err := jwt.Parse(signedString, keyFn(key), options...)
	if parsedJwt != nil {
		token.Token = parsedJwt
		token.SignedString = signedString
	}
	return token, err
}

// VerifyWithClaims verify a jwt token string with claims.
// Regardless of the result, it will return a *jwt.Token for Token.
func VerifyWithClaims(signedString string, key []byte, method jwt.SigningMethod, claims jwt.Claims, options ...jwt.ParserOption) (*Token, error) {
	token := new(Token)
	// check method defaults
	options = append(options, jwt.WithValidMethods([]string{method.Alg()}))
	// parsed with claims
	parsedJwt, err := jwt.ParseWithClaims(signedString, claims, keyFn(key), options...)
	if parsedJwt != nil {
		token.SignedString = signedString
		token.Token = parsedJwt
		// if parsed successfully, claims will be written.
		token.Claims = parsedJwt.Claims
	}
	return token, err
}
