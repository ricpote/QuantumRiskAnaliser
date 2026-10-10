module tlslab-modern

// Needs real Go >= 1.24 for X25519MLKEM768 (ML-KEM-768 hybrid key exchange).
// Uses the Go already installed on the machine; no legacy GODEBUG required.
go 1.24
