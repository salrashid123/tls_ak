package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/golang/glog"
	"github.com/gorilla/mux"

	"github.com/salrashid123/tls_ak/verifier"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const ()

var (
	grpcport        = flag.String("grpcport", "", "grpcport")
	applicationPort = flag.String("applicationPort", ":8081", "grpcport")
	tlsCert         = flag.String("tlsCert", "certs/server.crt", "tls Certificate")
	tlsKey          = flag.String("tlsKey", "certs/server.key", "tls Key")
	issuerCert      = flag.String("issuerCert", "certs/issuer_ca.crt", "tls Certificate")
	issuerKey       = flag.String("issuerKey", "certs/issuer_ca.key", "tls Key")
	eventLogPath    = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
	tpmDevice       = flag.String("tpmDevice", "/dev/tpmrm0", "TPMPath")

	httpServerName = flag.String("httpservername", "echo.domain.com", "SNI for http server")
	grpcServerName = flag.String("grpcServerName", "attestor.domain.com", "SNI for grpc server")

	tpm               *attest.TPM
	ek                *attest.EK
	ekpubBytes        []byte
	ekCert            *x509.Certificate
	akbytes           []byte
	nkBytes           []byte
	issuedTLSderBytes []byte

	attestationKeys = make(map[string]db) // map which holds the EKM value for a session and the database of attestation state
)

type db struct {
	//PlatformCert          *attributecert.AttributeCertificate // todo: read a platform cert and optionall return this to the verifier
	EKCert                *x509.Certificate
	AKPub                 crypto.PublicKey
	AttestationParameters *attest.AttestationParameters
	AKCSR                 *x509.CertificateRequest
	AKCert                *x509.Certificate
	Attested              bool
	Secret                []byte
	IssuedKey             *ecdsa.PublicKey
	IssuedCert            *x509.Certificate
	Nonce                 []byte
	AttestedKey           crypto.PublicKey
}

const ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

type linuxCmdChannel struct {
	io.ReadWriteCloser
}

// MeasurementLog implements CommandChannelTPM20.
func (cc *linuxCmdChannel) MeasurementLog() ([]byte, error) {
	return os.ReadFile(*eventLogPath)
}

type server struct {
	mu      sync.Mutex
	running bool

	// statusMap stores the serving status of the services this Server monitors.
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
	// Embed the unimplemented server
	verifier.UnimplementedVerifierServer
}

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
	EKM              string
	PeerIP           string
}

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
	oidPermanentIdentifier     = []int{1, 3, 6, 1, 5, 5, 7, 8, 3}
	oidHardwareModuleName      = []int{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

type permanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

type hardwareModuleName struct {
	SerialNumber []byte `asn1:"tag:4"`
}

func mustMarshal(val any) ([]byte, error) {
	data, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func marshalOtherName(oid asn1.ObjectIdentifier, value interface{}) (asn1.RawValue, error) {
	valueBytes, err := asn1.MarshalWithParams(value, "explicit,tag:0")
	if err != nil {
		return asn1.RawValue{}, err
	}
	b, err := asn1.MarshalWithParams(otherName{
		TypeID: oid,
		Value:  asn1.RawValue{FullBytes: valueBytes},
	}, "tag:0")
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

func (s *server) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)

	if in.Service == "" {
		// return overall status
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	}

	s.statusMap[verifier.Verifier_ServiceDesc.ServiceName] = healthpb.HealthCheckResponse_SERVING

	status, ok := s.statusMap[in.Service]
	if !ok {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_UNKNOWN}, grpc.Errorf(codes.NotFound, "unknown service")
	}

	// todo: optionally fill this in
	attestationKeys[evt.EKM] = db{
		EKCert: ekCert,
	}

	return &healthpb.HealthCheckResponse{Status: status}, nil
}

func (s *server) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func (s *server) List(ctx context.Context, in *healthpb.HealthListRequest) (*healthpb.HealthListResponse, error) {
	r := make(map[string]*healthpb.HealthCheckResponse)

	r[verifier.Verifier_ServiceDesc.ServiceName] = &healthpb.HealthCheckResponse{
		Status: healthpb.HealthCheckResponse_SERVING,
	}
	return &healthpb.HealthListResponse{Statuses: r}, nil
}

// NewServer returns a new Server.
func NewServer() *server {
	return &server{
		running:   true,
		statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	}
}

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	var newCtx context.Context
	var peerIPPort string
	p, ok := peer.FromContext(ctx)
	if ok {
		var err error
		peerIPPort, _, err = net.SplitHostPort(p.Addr.String())
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "could not get Remote IP")
		}
		glog.V(60).Infof("     Connected from peer %v", peerIPPort)
		newCtx = context.WithValue(ctx, contextKey("peerIP"), peerIPPort)
	} else {
		glog.Errorf("ERROR:  Could not extract peerInfo from TLS")
		return nil, status.Errorf(codes.PermissionDenied, "ERROR:  Could not extract peerInfo from TLS")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		glog.Errorf("ERROR:  Could get remote TLS")
		return nil, status.Errorf(codes.PermissionDenied, "ERROR: could not get remote TLS")
	}
	ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		glog.Errorf("ERROR:  Could getting EKM %v", err)
		return nil, status.Errorf(codes.PermissionDenied, "ERROR: error getting EKM")
	}
	glog.V(60).Infof("     EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	event := &event{
		EKM:    hex.EncodeToString(ekm),
		PeerIP: peerIPPort,
	}

	newCtx = context.WithValue(newCtx, contextEventKey, *event)
	return handler(newCtx, req)
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "UserIP is not in host:port format", http.StatusInternalServerError)
			return
		}
		userIP := net.ParseIP(ip)
		if userIP == nil {
			http.Error(w, "error parsing remote IP", http.StatusInternalServerError)
			return
		}

		ekm, err := r.TLS.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		glog.V(40).Infof("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		event := &event{
			PeerCertificates: r.TLS.PeerCertificates,
			EKM:              hex.EncodeToString(ekm),
			PeerIP:           ip,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) GetEK(ctx context.Context, in *verifier.GetEKRequest) (*verifier.GetEKResponse, error) {
	glog.V(2).Infof("======= GetEK ========")

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)
	if val, ok := attestationKeys[evt.EKM]; ok {
		if val.EKCert == nil {
			glog.Errorf("Error MakeCrGetEKedential requires HealthCheck was called first [%s]", evt.EKM)
			return &verifier.GetEKResponse{}, status.Errorf(codes.Internal, "Error GetEK v")
		}
	} else {
		glog.Errorf("Error GetEK requires HealthCheck was called first  [%s]", evt.EKM)
		return &verifier.GetEKResponse{}, status.Errorf(codes.Internal, "Error GetEK requires HealthCheck was called first")
	}

	return &verifier.GetEKResponse{
		EkPub:  ekpubBytes,
		EkCert: ekCert.Raw,
	}, nil

}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetAK ========")

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)
	if _, ok := attestationKeys[evt.EKM]; ok {
		if akbytes == nil {
			glog.Errorf("Error GetAK requires HealthCheck and GetEK was called first [%s]", evt.EKM)
			return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "Error HealthCheck and GetEK was called first v")
		}
	} else {
		glog.Errorf("Error GetAK requires HealthCheck was called first  [%s]", evt.EKM)
		return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "Error GetAK requires HealthCheck was called first")
	}

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("error loading ak %v", err)
		return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	attestParams := ak.AttestationParameters()
	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		glog.Errorf("ERROR:  encode attestation parameters AK %v", err)
		return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "ERROR:  could generate attestationParameters")
	}
	return &verifier.GetAKResponse{
		AttestationParameters: attestParametersBytes.Bytes(),
	}, nil
}

func (s *server) Attest(ctx context.Context, in *verifier.AttestRequest) (*verifier.AttestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Attest ========")

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)

	if _, ok := attestationKeys[evt.EKM]; ok {
		if akbytes == nil {
			glog.Errorf("Error Attest requires HealthCheck and GetEK and GetAK was called first [%s]", evt.EKM)
			return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "Error HealthCheck and and GetEK and GetAK  called first")
		}
	} else {
		glog.Errorf("Error Attest requires HealthCheck was called first  [%s]", evt.EKM)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "Error Attest requires HealthCheck and GetEK  called first")
	}

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	var encryptedCredentials attest.EncryptedCredential
	err = json.Unmarshal(in.EncryptedCredentials, &encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error decoding encryptedCredentials %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error decoding encryptedCredentials")
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	//secret, err := ak.ActivateCredentialWithEK(tpm, encryptedCredentials, *ek)
	if err != nil {
		glog.Errorf("ERROR:  error activating Credential  AK %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error activating Credentials")
	}

	return &verifier.AttestResponse{
		Secret: secret,
	}, nil
}

func (s *server) Quote(ctx context.Context, in *verifier.QuoteRequest) (*verifier.QuoteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Quote ========")

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)

	if _, ok := attestationKeys[evt.EKM]; ok {
		if akbytes == nil {
			glog.Errorf("Error Quote requires HealthCheck and GetEK GetAK Attest was called first [%s]", evt.EKM)
			return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "Error Quote requires GetEK GetAK  Attest called first")
		}
	} else {
		glog.Errorf("Error Attest requires GetEK GetAK  Attest called first  [%s]", evt.EKM)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "Error Quote requires GetEK GetAK  Attest called first")
	}

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	evtLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		glog.Errorf("     Error reading eventLog %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error reading eventLog: %v", err))
	}

	platformAttestation, err := tpm.AttestPlatform(ak, in.Nonce, &attest.PlatformAttestConfig{
		EventLog: evtLog,
	})
	if err != nil {
		glog.Errorf("ERROR: creating Attestation %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  creating Attestation ")
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		glog.Errorf("ERROR: encoding platformAttestationBytes %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  encoding platformAttestationBytes ")
	}

	return &verifier.QuoteResponse{
		PlatformAttestation: platformAttestationBytes.Bytes(),
	}, nil
}

func (s *server) GetTLSKey(ctx context.Context, in *verifier.GetAttestedKeyRequest) (*verifier.GetAttestedKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetTLSKey ========")

	evt := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", evt.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", evt.EKM)

	if _, ok := attestationKeys[evt.EKM]; ok {
		if nkBytes == nil {
			glog.Errorf("Error GetTLSKey requires HealthCheck and GetEK GetAK Attest was called first [%s]", evt.EKM)
			return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Error GetTLSKey requires GetEK GetAK  Attest called first")
		}
	} else {
		glog.Errorf("Error GetTLSKey requires GetEK GetAK  Attest called first  [%s]", evt.EKM)
		return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Error GetTLSKey requires GetEK GetAK  Attest called first")
	}

	nk, err := tpm.LoadKey(nkBytes)
	if err != nil {
		glog.Errorf("ERROR:  could not load tls key%v", err)
		return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error tls key"))
	}
	defer nk.Close()

	keyCertificationBytes := new(bytes.Buffer)
	err = json.NewEncoder(keyCertificationBytes).Encode(nk.CertificationParameters())
	if err != nil {
		glog.Errorf("ERROR: encoding keyCertificationBytes %v", err)
		return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding keyCertificationBytes "))
	}

	return &verifier.GetAttestedKeyResponse{
		Certificate:      issuedTLSderBytes,
		KeyCertification: keyCertificationBytes.Bytes(),
	}, nil
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	glog.V(10).Infof("Inbound HTTP request from: %s", val.PeerIP)
	fmt.Fprint(w, "ok")
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		return 0
	}

	var err error
	glog.V(2).Info("Getting EKCert")

	// first get the ek so we can stuff it into the platform cert

	var config *attest.OpenConfig
	if !slices.Contains(TPMDEVICES, *tpmDevice) {
		glog.Info("Opening swtpm socket")
		rwc, err := openTPM(*tpmDevice)
		if err != nil {
			glog.Errorf("can't open TPM %q: %v", *tpmDevice, err)
			return 1
		}
		defer func() {
			rwc.Close()
		}()

		//rwr := transport.FromReadWriter(rwc)
		config = &attest.OpenConfig{
			CommandChannel: &linuxCmdChannel{rwc},
		}
	}

	tpm, err = attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("error opening TPM %v", err)
		return 1
	}
	defer tpm.Close()

	r, err := tpm.Info()
	if err != nil {
		glog.Errorf("error getting TPMInfo %v", err)
		os.Exit(1)
	}

	glog.V(10).Infof("VendorInfo: %s\n", r.VendorInfo)
	glog.V(10).Infof("FirmwareVersionMajor: %d\n", r.FirmwareVersionMajor)
	glog.V(10).Infof("FirmwareVersionMinor: %d\n", r.FirmwareVersionMinor)
	glog.V(10).Infof("Manufacturer: %s\n", r.Manufacturer)
	glog.V(10).Infof("VendorInfo: %s\n", r.VendorInfo)

	eks, err := tpm.EKs()
	if err != nil {
		glog.Errorf("error getting EK %v", err)
		return 1
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("ECCert with available Issuer: %s", e.Certificate.Issuer)
		}
	}

	if len(eks) == 0 {
		glog.Error("error no EK found")
		return 1
	}

	// use the  ek at 0 for now...
	ek = &eks[0]

	if ek.Public == nil {
		glog.Error("error no Public not found")
		return 1
	}

	ekpubBytes, err = x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		glog.Errorf("ERROR:  could  marshall public key %v", err)
		return 1
	}

	if ek.Certificate != nil {
		ekCert = ek.Certificate
	}
	// generate the attestation key
	// TODO: see how to get the GCE signed attestation key:
	// https://github.com/salrashid123/gcp-vtpm-ek-ak
	akConfig := &attest.AKConfig{
		Parent: &attest.ParentKeyConfig{
			Algorithm: attest.RSA,
			Handle:    0x81000001, // SRK, pg 29 https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
		},
	}
	//akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		glog.Errorf("ERROR:  could not get AK %v", err)
		return 1
	}
	defer ak.Close(tpm)
	akbytes, err = ak.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could marshall AK %v", err)
		return 1
	}

	// simulate creating a CSR to send to some CA
	//  the spiffie and CN i'm just making up and is totally optional..its the serial number for the EK
	issuerCertBytes, err := os.ReadFile(*issuerCert)
	if err != nil {
		glog.Errorf("Error Reading root ca %v", err)
		return 1
	}

	rcblock, _ := pem.Decode(issuerCertBytes)

	rcert, err := x509.ParseCertificate(rcblock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading issuercertificate %v", err)
		return 1
	}
	issuerKeyBytes, err := os.ReadFile(*issuerKey)
	if err != nil {
		glog.Errorf("ERROR:  error loading issuerkey %v", err)
		return 1
	}
	rblock, _ := pem.Decode(issuerKeyBytes)
	issuerPrivateKey, err := x509.ParsePKCS8PrivateKey(rblock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading privatekey %v", err)
		return 1
	}

	issuerRootCAs := x509.NewCertPool()
	if !issuerRootCAs.AppendCertsFromPEM(issuerCertBytes) {
		glog.Errorf("no root Issuer certs parsed from file ")
		return 1
	}

	// now issue an AK x509

	var akcsrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "attestor.domain.com",
		},
		DNSNames:           []string{"attestor.domain.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	aks, err := NewTPMCrypto(&TPM{
		TPM: tpm,
		AK:  ak,
	})
	if err != nil {
		glog.Errorf("Failed to create CSR: %s", err)
		os.Exit(1)
	}

	akcsrBytes, err := x509.CreateCertificateRequest(rand.Reader, &akcsrtemplate, aks)
	if err != nil {
		glog.Errorf("Failed to create CSR: %s", err)
		os.Exit(1)
	}
	akpemcsr := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: akcsrBytes,
		},
	)

	akcsr, err := x509.ParseCertificateRequest(akcsrBytes)
	if err != nil {
		glog.Errorf("Failed to parse CSR: %s", err)
		os.Exit(1)
	}
	// you can send this CSR to a CA
	glog.V(5).Infof("AK CSR \n%s\n", string(akpemcsr))

	// pretend this is the CA which will sign the AK CSR
	var aknotBefore time.Time
	aknotBefore = time.Now()

	aknotAfter := aknotBefore.Add(time.Hour * 24 * 1)

	akserialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	akserialNumber, err := rand.Int(rand.Reader, akserialNumberLimit)
	if err != nil {
		glog.Errorf("Failed to generate serial number: %v", err)
		return 1
	}

	// add tpm SAN as "OtherName"

	// pg 56:
	//    https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf

	// Provider Name is from pg 10 https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
	simulatorHW := "SIM0" // we'll assume its a simulator
	var buf bytes.Buffer
	buf.WriteString(simulatorHW)
	buf.WriteString(":")
	buf.Write(ekCert.AuthorityKeyId)
	buf.WriteString(":")
	buf.Write(ekCert.SerialNumber.Bytes())

	pic, err := marshalOtherName(oidHardwareModuleName, hardwareModuleName{
		SerialNumber: buf.Bytes(),
	})
	if err != nil {
		glog.Errorf("Failed to create oidHardwareModuleName:  %v", err)
		return 1
	}

	h := sha256.New()
	h.Write([]byte(ekCert.Raw))
	ekHash := h.Sum(nil)

	pi, err := marshalOtherName(oidPermanentIdentifier, permanentIdentifier{
		IdentifierValue: hex.EncodeToString(ekHash),
	})
	if err != nil {
		glog.Errorf("Failed to create permanentIdentifier %v", err)
		return 1
	}

	cc, err := mustMarshal([]asn1.RawValue{pic, pi})
	if err != nil {
		glog.Errorf("Failed to generate serial number:  %v", err)
		return 1
	}

	extSubjectAltName := pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    cc,
	}

	// TODO: set the correct extensions
	// I'm injecting the policy here...this too is just optional and while its not even used, i don't know if this is entirely applicable/correct
	// pg4  https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf
	// 2.23.133.11.1.1 tcg-cap-verifiedTPMResidency
	// 2.23.133.11.1.2 tcg-cap-verifiedTPMFixed
	verifiedTPMResidency := asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	verifiedTPMFixed := asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}
	verifiedTPMRestricted := asn1.ObjectIdentifier{2, 23, 133, 11, 1, 3}
	aktemplate := x509.Certificate{
		SerialNumber: akserialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         akcsr.Subject.CommonName,
		},
		NotBefore: aknotBefore,
		NotAfter:  aknotAfter,
		//DNSNames:              csr.DNSNames,
		KeyUsage: x509.KeyUsageDigitalSignature,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{verifiedTPMResidency, verifiedTPMFixed, verifiedTPMRestricted},
		ExtraExtensions:       []pkix.Extension{extSubjectAltName},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &aktemplate, rcert, ak.Public(), issuerPrivateKey)
	if err != nil {
		glog.Errorf("Failed to create certificate: %v", err)
		return 1
	}
	// akcert, err := x509.ParseCertificate(derBytes)
	// if err != nil {
	// 	glog.Errorf("Failed to create certificate: %v", err)
	// 	return 1
	// }

	akCSRPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)

	glog.V(2).Infof("Issued AKPublic \n%s", string(akCSRPEM))

	// optionally issue an x509 cert using this AK
	// THis cert isn't used in this flow but you can use this x509 later on and not having to do remote attestation all over again
	//  with new clients

	// now crate the TLS EC key on the TPM
	// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L147
	//   tpm2.FlagSignerDefault ^ tpm2.FlagRestricted
	// where
	// FlagSignerDefault = FlagSign | FlagRestricted | FlagFixedTPM | FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	kConfig := &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
		// Parent: &attest.ParentKeyConfig{
		// 	Algorithm: attest.RSA,
		// 	Handle:    0x81000001, // default RSA SRK
		// },
	}
	nk, err := tpm.NewKey(ak, kConfig)
	if err != nil {
		glog.Errorf("ERROR:  error creating key  %v", err)
		return 1
	}
	err = ak.Close(tpm)
	if err != nil {
		glog.Errorf("ERROR:  error closing ak  %v", err)
		return 1
	}
	defer nk.Close()

	nkBytes, err = nk.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could not marshall newkey %v", err)
		return 1
	}

	pubKey, ok := nk.Public().(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("Could not assert the public key to ec public key")
		return 1
	}

	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("Could not MarshalPKIXPublicKey ec public key")
		return 1
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeybytes,
		},
	)

	glog.V(2).Infof("Generated ECC Public \n%s", string(pubkeyPem))

	// **********************************************************

	// extract the crypto.Signer from the TLS key

	signer, err := nk.Private(nk.Public())
	if err != nil {
		glog.Errorf("ERROR: getting crypto.Signer from generated key %v", err)
		return 1
	}

	// generate a CSR
	glog.V(10).Infof("        Issuing Cert ========")

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24) // valid for a day

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		glog.Errorf("ERROR: Failed to generate serial number: %v", err)
		return 1
	}

	deviceSerialNumber := uuid.New().String()
	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			SerialNumber:       deviceSerialNumber,
			CommonName:         fmt.Sprintf("tpm_server %s", deviceSerialNumber),
		},
		DNSNames: []string{*httpServerName},
		Extensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 4, 5}, // id-at-serialNumber X520SerialNumber
			Value: []byte(deviceSerialNumber),
		}},
		//ExtraExtensions:    []pkix.Extension{extSubjectAltName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// create the CSR but note the private key is the EC keys's "signer"
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, signer)
	if err != nil {
		glog.Errorf("ERROR:  error creating csr %v", err)
		return 1
	}

	csrpemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	glog.V(20).Infof("      CSR \n%s\n", string(csrpemdata))

	// simulate marshal/unmarshalling the csr on whatever CA you have.
	//  The CA is should be something the verifier trusts.
	//  Here the remote CA is local, just pretend we issue a csr and get it signed by that CA.
	// in an alternative flow, the CSR here could even be sent back to each verifier...the verifier
	//  would then issue the x509 and then return to the attestor.
	//   the attestor would startTLS  and listening using that (ofcourse that flow requires new methods/flows)
	clientCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		glog.Errorf("ERROR:  error ParseCertificateRequest %v", err)
		return 1
	}

	// now use certain fields within the CSR and the overall template to issue the cert on the CA

	// I'm injecting the policy here...this too is just optional and while its not even used, i don't know if this is entirely applicable/correct
	// pg4  https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf
	// 2.23.133.11.1.1 tcg-cap-verifiedTPMResidency
	// 2.23.133.11.1.2 tcg-cap-verifiedTPMFixed

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			SerialNumber:       clientCSR.Subject.SerialNumber,
			CommonName:         clientCSR.Subject.CommonName, // from CSR
		},
		DNSNames:    clientCSR.DNSNames, // from CSR
		URIs:        clientCSR.URIs,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Extensions:  clientCSR.Extensions,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		//ExtraExtensions:       []pkix.Extension{extSubjectAltName},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{verifiedTPMResidency, verifiedTPMFixed},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// now issue the cert using the local CA
	issuedTLSderBytes, err = x509.CreateCertificate(rand.Reader, &template, rcert, clientCSR.PublicKey, issuerPrivateKey)
	if err != nil {
		glog.Errorf("ERROR:  Failed to create certificate: %s\n", err)
		return 1
	}

	p, err := x509.ParseCertificate(issuedTLSderBytes)
	if err != nil {
		glog.Errorf("ERROR:  Failed to  parse certificate: %s", err)
		return 1
	}
	glog.V(10).Infof("        cert Issuer %s\n", p.Issuer)

	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuedTLSderBytes})
	glog.V(10).Infof("        Issued Certificate ========\n%s\n", c)

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(p.PublicKey)
	if err != nil {
		glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
		return 1
	}
	kpem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	glog.V(2).Infof("        Issued certificate tied to PubicKey ========\n%s\n", kpem)

	// use the EC key to launch the HTTPs server
	// again, note the privatekey is the signer
	ctx := context.Background()
	tlsCrt := tls.Certificate{
		Certificate: [][]byte{p.Raw, rcert.Raw},
		Leaf:        p,
		PrivateKey:  signer,
	}

	errs, _ := errgroup.WithContext(ctx)
	errs.Go(func() error {
		router := mux.NewRouter()
		router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)
		server := &http.Server{
			Addr:    *applicationPort,
			Handler: eventsMiddleware(router),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCrt},
			},
		}

		http2.ConfigureServer(server, &http2.Server{})
		glog.V(2).Infof("Starting HTTP Server on port %s", *applicationPort)

		lis, err := net.Listen("tcp", *applicationPort)
		if err != nil {
			glog.Errorf("        Error Listening \n%v\n", err)
			return fmt.Errorf("ERROR: listening: %v", err)
		}

		return server.ServeTLS(lis, "", "")
	})

	// if err := errs.Wait(); err != nil {
	// 	glog.Errorf("ERROR:  error startingTLS %v", err)
	// 	return &verifier.StartTLSResponse{Status: false}, status.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error startingTLS %v", err))
	// }
	// launch grpc attestation server

	defaultCerts, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		glog.Errorf("failed to create default certs: %v", err)
		return 1
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{defaultCerts},
	}
	ce := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Errorf("failed to listen: %v", err)
		return 1
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)
	srv := NewServer()
	verifier.RegisterVerifierServer(s, srv)
	healthpb.RegisterHealthServer(s, srv)

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := s.Serve(lis); err != nil {
			glog.Errorf("Error in listenlisten: %s\n", err)
			return
		}
	}()
	<-done

	return 0
}

type TPM struct {
	_ crypto.Signer
	//_ crypto.MessageSigner // introduced in https://tip.golang.org/doc/go1.25#cryptopkgcrypto
	_   crypto.MessageSigner
	TPM *attest.TPM
	AK  *attest.AK
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.TPM == nil {
		return TPM{}, fmt.Errorf("AK TPM cannot be null")
	}

	if conf.AK == nil {
		return TPM{}, fmt.Errorf("AK cannot be null")
	}

	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	return t.AK.Public()
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.AK.SignMsg(t.TPM, digest, opts)
}

func (t TPM) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return t.AK.SignMsg(t.TPM, msg, opts)
}
