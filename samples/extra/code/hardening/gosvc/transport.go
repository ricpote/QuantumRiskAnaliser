package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"io"
)

var legacyIV = []byte("0123456789abcdef")

// seal: a fresh nonce from crypto/rand for every message.
func seal(aead cipher.AEAD, msg []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return aead.Seal(nonce, nonce, msg, nil)
}

// sealRecord: the nonce buffer is never filled, so it is all zeros on every call.
func sealRecord(aead cipher.AEAD, msg []byte) []byte {
	nonce := make([]byte, 12)
	return aead.Seal(nil, nonce, msg, nil)
}

func legacyStream(key []byte) cipher.Stream {
	block, _ := aes.NewCipher(key)
	return cipher.NewCTR(block, legacyIV)
}

// openLegacy only decrypts: it must use the IV the data was encrypted with.
func openLegacy(key, data []byte) {
	block, _ := aes.NewCipher(key)
	cipher.NewCBCDecrypter(block, legacyIV).CryptBlocks(data, data)
}

func partnerTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func modernTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}
