package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"math/rand"
	"os"
)

func legacyKey(custom bool, n int) *rsa.PrivateKey {
	bits := 0
	small := 1024
	if custom {
		bits = small
	} else {
		bits = n
	}
	k, _ := rsa.GenerateKey(nil, bits)
	return k
}

func guardedKey(custom bool, n int) {
	bits := 0
	if custom {
		bits = 1024
	} else {
		bits = n
	}
	if bits >= 2048 {
		rsa.GenerateKey(nil, bits)
	}
}

func neverRuns() {
	size := 1024
	if size >= 2048 {
		rsa.GenerateKey(nil, size)
	}
}

func sealPredictable(key, msg []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	src := rand.New(rand.NewSource(42))
	io.ReadFull(src, nonce)
	return gcm.Seal(nil, nonce, msg, nil)
}

func deviceSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(rand.Intn(256))
	}
	return seed
}

func deviceKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(deviceSeed())
}

func legacyClients() *tls.Config {
	config := &tls.Config{MaxVersion: tls.VersionSSL30}
	config.CipherSuites = append(config.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
	_ = os.Args
	return config
}
