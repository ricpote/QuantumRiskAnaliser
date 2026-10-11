package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func sign(claims jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return t.SignedString([]byte("0123456789abcdef"))
}

func peek(s string) {
	tok, _, _ := new(jwt.Parser).ParseUnverified(s, jwt.MapClaims{})
	fmt.Println(tok)
}

func main() {}
