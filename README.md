# jwtx

jwtx is simple jwt helper base on `github.com/golang-jwt/jwt/v5`.

## install 
```bash
go get github.com/ginx-contribs/jwtx@latest
```

## usage

```go
package main

import (
	"github.com/ginx-contribs/jwtx"
	"github.com/golang-jwt/jwt/v5"
	"log"
)

func main() {
	key := []byte("my key")
	token, err := jwtx.Issue(key, jwt.SigningMethodHS256)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(token.SignedString)

	verifiedToken, err := jwtx.Verify(token.SignedString, key, jwt.SigningMethodHS256)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(verifiedToken.SignedString)
}
```