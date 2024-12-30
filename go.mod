module main

go 1.22.7

toolchain go1.22.10

require (
	github.com/golang/glog v1.2.2
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	//github.com/salrashid123/tls_ak/verifier v0.0.0
	golang.org/x/net v0.31.0
	golang.org/x/sync v0.9.0
	google.golang.org/grpc v1.69.2
)

require (
	github.com/salrashid123/gcp-vtpm-ek-ak/parser v0.0.0-20241230103405-619d349db58b
	github.com/salrashid123/tls_ak/verifier v0.0.0-20241227161314-8d2a0bc59372
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.3.0 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241113202542-65e8d215514f // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)

//replace github.com/salrashid123/tls_ak/verifier => ./verifier
