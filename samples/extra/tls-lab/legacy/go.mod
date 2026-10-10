module tlslab-legacy

// `go 1.21.13` is deliberate. Go >= 1.22 disables RSA key-transport, 3DES and TLS 1.0 by
// default, but a newer Go building this module keeps Go 1.21's default GODEBUG
// (tlsrsakex=1, tls3des=1, tls10server=1), so the obsolete profile still works.
// It does NOT download Go 1.21: the installed Go builds it (checked with Go 1.24 and 1.26).
// If a future Go drops these settings, use the Docker image, which pins Go 1.24.
go 1.21.13
