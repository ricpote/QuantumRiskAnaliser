// tlslab-modern: the PQ / current-crypto half of the lab.
//
//	go run .
//
// 127.0.0.1:8443  pq-modern         TLS 1.3 only, X25519MLKEM768 preferred, ECDSA P-256 cert
// 127.0.0.1:8444  classical-tls13   TLS 1.2-1.3, X25519/P-256 only (no PQ), ECDSA P-256 cert
// 127.0.0.1:8446  pq-with-fallback  TLS 1.3 + X25519MLKEM768 for modern clients, TLS 1.2 ECDHE+RSA-auth fallback for legacy ones
// 127.0.0.1:8447  pq-only           TLS 1.3, ONLY X25519MLKEM768 (classical clients fail)
// 127.0.0.1:2525  smtp-starttls     SMTP + STARTTLS -> TLS 1.2/1.3 classical, RSA-2048 cert
// 127.0.0.1:5433  postgres-ssl      Postgres SSLRequest -> TLS 1.3 + X25519MLKEM768
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func addr(port string) string {
	h := os.Getenv("LAB_HOST")
	if h == "" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, port)
}

func mkCert(cn string, key crypto.Signer, sig x509.SignatureAlgorithm, notAfter time.Time) tls.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"QuantumTrace Lab"}},
		DNSNames:              []string{cn, "localhost"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sig,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serve(name, addr string, cfg *tls.Config) {
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	log.Printf("%-17s https://%s", name, addr)
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

func serveSMTP(addr string, cfg *tls.Config) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%-17s smtp://%s (STARTTLS)", "smtp-starttls", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(c)
			fmt.Fprint(c, "220 mail.lab ESMTP QuantumTrace-lab\r\n")
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				cmd := strings.ToUpper(strings.TrimSpace(line))
				switch {
				case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
					fmt.Fprint(c, "250-mail.lab\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
				case cmd == "STARTTLS":
					fmt.Fprint(c, "220 2.0.0 Ready to start TLS\r\n")
					t := tls.Server(c, cfg)
					t.Handshake()
					return
				case cmd == "QUIT":
					fmt.Fprint(c, "221 bye\r\n")
					return
				default:
					fmt.Fprint(c, "502 unknown\r\n")
				}
			}
		}(c)
	}
}

func servePostgres(addr string, cfg *tls.Config) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%-17s postgres://%s (SSLRequest)", "postgres-ssl", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 8)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			if buf[4] == 0x04 && buf[5] == 0xd2 && buf[6] == 0x16 && buf[7] == 0x2f { // 80877103
				c.Write([]byte("S"))
				tls.Server(c, cfg).Handshake()
			}
		}(c)
	}
}

func main() {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	year := time.Now().Add(365 * 24 * time.Hour)
	modern := mkCert("pq.lab", ec, x509.ECDSAWithSHA256, year)
	classic := mkCert("classic.lab", ec, x509.ECDSAWithSHA256, year)
	mail := mkCert("mail.lab", rsaKey, x509.SHA256WithRSA, year)

	go serve("pq-modern", addr("8443"), &tls.Config{
		Certificates: []tls.Certificate{modern}, MinVersion: tls.VersionTLS13, // CurvePreferences nil -> Go 1.24 default: X25519MLKEM768 first
	})
	go serve("classical-tls13", addr("8444"), &tls.Config{
		Certificates: []tls.Certificate{classic}, MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	})
	// Forward-secret only (ECDHE for key exchange, RSA only for auth) so this doesn't need
	// the tlsrsakex GODEBUG opt-in (RSA key transport lives in legacy/, port 8445); still a real classical fallback.
	go serve("pq-with-fallback", addr("8446"), &tls.Config{
		Certificates: []tls.Certificate{mail}, MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	// NB: Go >= 1.24 ignores the ORDER of CurvePreferences and always prefers X25519MLKEM768
	go serve("pq-only", addr("8447"), &tls.Config{
		Certificates: []tls.Certificate{modern}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	go serveSMTP(addr("2525"), &tls.Config{Certificates: []tls.Certificate{mail}, MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	go servePostgres(addr("5433"), &tls.Config{Certificates: []tls.Certificate{modern}, MinVersion: tls.VersionTLS13})
	log.Printf("modern lab ready")
	select {}
}
