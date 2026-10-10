module tlslab-handshakes

// Pinned to the same old toolchain as ../../legacy: this tool dials the RSA
// key-transport / 3DES suites against the legacy profile, which newer Go
// refuses to speak at all (see legacy/go.mod for why). Dialing the modern/PQ
// profiles (8443/8444/8446/8447) still works from this toolchain, it just
// won't negotiate X25519MLKEM768 since this Go predates ML-KEM support —
// acceptable here since this is a manual recording helper, not the
// automated test suite.
go 1.21.13
