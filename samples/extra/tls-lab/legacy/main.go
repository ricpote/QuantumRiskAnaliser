// tlslab-legacy: the obsolete-crypto half of the lab. Built with an old Go
// toolchain (pinned in go.mod) because Go >= 1.22 disables RSA key-transport,
// 3DES and TLS 1.0 by default, and Go >= 1.27 removed the GODEBUG opt-ins
// that used to bring them back.
//
//	go run .
//
// 127.0.0.1:8445  legacy  TLS 1.0-1.2, RSA key transport, CBC, 3DES, RSA-2048 SHA-1 cert (expired)
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func addr(port string) string {
	h := os.Getenv("LAB_HOST")
	if h == "" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, port)
}

func main() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "legacy.lab", Organization: []string{"QuantumTrace Lab"}},
		DNSNames:              []string{"legacy.lab", "localhost"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired yesterday
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rsaKey.Public(), rsaKey)
	if err != nil {
		tmpl.SignatureAlgorithm = x509.SHA256WithRSA
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, rsaKey.Public(), rsaKey)
	}
	if err != nil {
		log.Fatal(err)
	}
	legacy := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: rsaKey}

	a := addr("8445")
	ln, err := tls.Listen("tcp", a, &tls.Config{
		Certificates: []tls.Certificate{legacy}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		log.Fatalf("legacy: %v", err)
	}
	log.Printf("%-17s https://%s", "legacy", a)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			r.ReadString('\n')
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n")
		}(c)
	}
}
