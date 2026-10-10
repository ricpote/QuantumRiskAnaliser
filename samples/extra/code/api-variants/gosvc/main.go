package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/sha3"
)

func legacyKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

func currentKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}

func fingerprint(b []byte) [28]byte {
	return sha3.Sum224(b)
}

func main() {
	k, _ := currentKey()
	fmt.Println(k.N.BitLen())
}
