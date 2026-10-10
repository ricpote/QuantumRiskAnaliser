package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var signingKey = []byte("hunter2hunter2")

func issueSession(user string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user, "exp": time.Now().Add(time.Hour).Unix()})
	return t.SignedString(signingKey)
}

func parsePartner(tokenString string, pub any) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		// type check on the method family, not an algorithm choice
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256", "PS256"}))
}

func debugClaims(tokenString string) jwt.Claims {
	tok, _ := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return jwt.UnsafeAllowNoneSignatureType, nil
	})
	return tok.Claims
}

func main() {
	s, _ := issueSession("alice")
	fmt.Println(s)
}
