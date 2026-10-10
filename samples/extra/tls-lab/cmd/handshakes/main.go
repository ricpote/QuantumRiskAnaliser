// handshakes: real Go TLS clients against the lab, used to record reference pcaps.
//
//	GODEBUG=tlsrsakex=1,tls3des=1 go run ./cmd/handshakes
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func dial(name, addr string, cfg *tls.Config) {
	cfg.InsecureSkipVerify = true
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		fmt.Printf("%-34s %s  ERR %v\n", name, addr, err)
		return
	}
	st := c.ConnectionState()
	fmt.Printf("%-34s %s  %s %s\n", name, addr, tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	c.Close()
}

func main() {
	dial("hybrid PQ (Go default client)", "127.0.0.1:8443", &tls.Config{ServerName: "pq.lab"})
	dial("PQ offered, classical server", "127.0.0.1:8444", &tls.Config{ServerName: "classic.lab"})
	dial("classical-only client", "127.0.0.1:8443", &tls.Config{ServerName: "pq.lab", CurvePreferences: []tls.CurveID{tls.X25519}})
	dial("TLS 1.2 ECDHE (cert in clear)", "127.0.0.1:8444", &tls.Config{ServerName: "classic.lab", MaxVersion: tls.VersionTLS12})
	dial("TLS 1.2 RSA key transport", "127.0.0.1:8445", &tls.Config{ServerName: "legacy.lab", MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}})
	dial("TLS 1.0 3DES", "127.0.0.1:8445", &tls.Config{ServerName: "legacy.lab", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}})
	dial("PQ-only server", "127.0.0.1:8447", &tls.Config{ServerName: "pq.lab"})
	dial("PQ server, TLS 1.2 fallback client", "127.0.0.1:8446", &tls.Config{ServerName: "mail.lab", MaxVersion: tls.VersionTLS12})
}
