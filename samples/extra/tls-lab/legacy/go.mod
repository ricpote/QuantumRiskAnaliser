module tlslab-legacy

// Pinned (not just a minimum): Go >= 1.22 disables RSA key-transport and 3DES
// cipher suites and TLS 1.0 by default, and Go >= 1.27 hard-removes the
// GODEBUG opt-ins (tlsrsakex, tls3des, tls10server) that used to bring them
// back, after their deprecation window expired. This profile exists
// specifically to demonstrate those obsolete algorithms, so it is built with
// the last Go version where they still work. `go build` fetches this
// toolchain automatically for this module only; it does not touch the Go
// installed system-wide.
go 1.21.13
