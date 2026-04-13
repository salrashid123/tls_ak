module main

go 1.26.2

require (
	github.com/golang/glog v1.2.5
	github.com/google/go-attestation v0.6.0
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.8
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/salrashid123/tls_ak/verifier v0.0.0
	golang.org/x/net v0.47.0
	golang.org/x/sync v0.18.0
	google.golang.org/grpc v1.77.0
)

require (
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260307011055-895ec9019dd7 // indirect
	github.com/containerd/containerd v1.7.30 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-eventlog v0.0.3-0.20260305053119-5cd85087f9f9 // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/salrashid123/tls_ak/verifier => ./verifier
