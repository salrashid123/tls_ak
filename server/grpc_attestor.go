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
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"flag"
	"fmt"
	"math/big"
	mrnd "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"

	"github.com/salrashid123/tpm_attested_mtls/verifier"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	grpcport        = flag.String("grpcport", "", "grpcport")
	applicationPort = flag.String("applicationPort", ":8081", "grpcport")
	tlsCert         = flag.String("tlsCert", "../certs/server.crt", "tls Certificate")
	tlsKey          = flag.String("tlsKey", "../certs/server.key", "tls Key")
	issuerCert      = flag.String("issuerCert", "../certs/issuer_ca.crt", "tls Certificate")
	issuerKey       = flag.String("issuerKey", "../certs/issuer_ca.key", "tls Key")
	eventLogPath    = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
	tpmDevice       = flag.String("tpmDevice", "/dev/tpm0", "TPMPath")
	contextsPath    = flag.String("contextsPath", "/tmp/contexts", "Contexts Path")
	attestationKeys = make(map[string][]byte)

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
	ek           attest.EK
	letterRunes  = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	dynamicCerts tls.Certificate
	signer       crypto.PrivateKey
	quit         = make(chan bool)
)

const ()

type server struct {
	mu      sync.Mutex
	running bool
}

type echoserver struct{}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	glog.V(40).Infof(">> inbound request")
	return handler(ctx, req)
}

// func initServerCerts(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
// 	return &dynamicCerts, nil
// }

func (s *server) GetEK(ctx context.Context, in *verifier.GetEKRequest) (*verifier.GetEKResponse, error) {
	glog.V(2).Infof("======= GetEK ========")
	if ek.Public != nil {
		pubBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
		if err != nil {
			glog.Errorf("ERROR:  could  marshall public key %v", err)
			return &verifier.GetEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   could  marshall public key"))
		}

		if ek.Certificate != nil {
			return &verifier.GetEKResponse{
				EkPub:  pubBytes,
				EkCert: ek.Certificate.Raw,
			}, nil
		}
		return &verifier.GetEKResponse{
			EkPub: pubBytes,
		}, nil
	} else {
		glog.Errorf("ERROR:  could  EK not set")
		return &verifier.GetEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could  not set"))
	}
}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetAK ========")
	if s.running {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   Server already running"))
	}

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	var attestParams attest.AttestationParameters

	if _, err := os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid)); err == nil {
		akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
		if err != nil {
			glog.Errorf("ERROR:  error reading ak file at path %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
		}
		ak, err := tpm.LoadAK(akBytes)
		if err != nil {
			glog.Errorf("ERROR:  error loading ak AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
		}
		defer ak.Close(tpm)
		attestParams = ak.AttestationParameters()
	} else {
		akConfig := &attest.AKConfig{}
		ak, err := tpm.NewAK(akConfig)
		if err != nil {
			glog.Errorf("ERROR:  could not get AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could get AK"))
		}
		attestParams = ak.AttestationParameters()
		akBytes, err := ak.Marshal()
		if err != nil {
			glog.Errorf("ERROR:  could not marshall AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could get AK"))
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid), akBytes, 0600); err != nil {
			glog.Errorf("ERROR:  could not write ak to file %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  writing AK to file"))
		}
	}
	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		glog.Errorf("ERROR:  encode attestation parameters AK %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could generate attestationParameters"))
	}
	return &verifier.GetAKResponse{
		Ak: attestParametersBytes.Bytes(),
	}, nil
}

func (s *server) Attest(ctx context.Context, in *verifier.AttestRequest) (*verifier.AttestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Attest ========")
	if s.running {
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   Server already running"))
	}

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Attest without Attestion Key; first run GetAK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot Attest without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	var encryptedCredentials attest.EncryptedCredential
	err = json.Unmarshal(in.EncryptedCredentials, &encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error decoding encryptedCredentials %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error decoding encryptedCredentials"))
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error activating Credential  AK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error activating Credentials"))
	}

	return &verifier.AttestResponse{
		Secret: secret,
	}, nil
}

func (s *server) Quote(ctx context.Context, in *verifier.QuoteRequest) (*verifier.QuoteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Quote ========")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Quote without Attestion Key; first run GetAK %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot Quote without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	evtLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		glog.Errorf("     Error reading eventLog %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error reading eventLog: %v", err))
	}

	platformAttestation, err := tpm.AttestPlatform(ak, in.Nonce, &attest.PlatformAttestConfig{
		EventLog: evtLog,
	})
	if err != nil {
		glog.Errorf("ERROR: creating Attestation %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  creating Attestation "))
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		glog.Errorf("ERROR: encoding platformAttestationBytes %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding platformAttestationBytes "))
	}

	return &verifier.QuoteResponse{
		PlatformAttestation: platformAttestationBytes.Bytes(),
	}, nil
}

func (s *server) NewKey(ctx context.Context, in *verifier.NewKeyRequest) (*verifier.NewKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= NewKey ========")

	if s.running {
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   Server already running"))
	}
	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:   cannot create NewKey without Attestion Key; first run GetAK %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot create NewKey without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	// todo: support other keytypes,sizes
	kConfig := &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
	}
	nk, err := tpm.NewKey(ak, kConfig)
	if err != nil {
		glog.Errorf("ERROR:  error creating key  %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: creating key"))
	}

	nkBytes, err := nk.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could not marshall newkey %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could marshall newkey"))
	}
	if err := os.WriteFile(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid), nkBytes, 0600); err != nil {
		glog.Errorf("ERROR:  could not write ak to file %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  writing AK to file"))
	}

	pubKey, ok := nk.Public().(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("Could not assert the public key to rsa public key")
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: Could not assert the public key to rsa public key"))
	}

	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("Could not MarshalPKIXPublicKey rsa public key")
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: Could not MarshalPKIXPublicKey rsa public key"))
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubkeybytes,
		},
	)

	keyCertificationBytes := new(bytes.Buffer)
	err = json.NewEncoder(keyCertificationBytes).Encode(nk.CertificationParameters())
	if err != nil {
		glog.Errorf("ERROR: encoding keyCertificationBytes %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding keyCertificationBytes "))
	}

	return &verifier.NewKeyResponse{
		Public:           []byte(pubkeyPem),
		KeyCertification: keyCertificationBytes.Bytes(),
	}, nil
}

func (s *server) Sign(ctx context.Context, in *verifier.SignRequest) (*verifier.SignResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Sign ========")

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  error opening TPM %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error opening TPM"))
	}
	defer rwc.Close()

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Sign without signing key Key; first run GetAK then NewKey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:    cannot Sign without signing key Key; first run GetAK then NewKey "))
	}

	skBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
	if err != nil {
		glog.Errorf("ERROR:  error reading sigining key file at path %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading signing file at path"))
	}

	var sig []byte

	sk, err := tpm.LoadKey(skBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading signing key %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading signing key"))
	}
	defer sk.Close()

	pk, err := sk.Private(sk.Public())
	if err != nil {
		glog.Errorf("ERROR:  error loading privatekey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading signing privatekey"))
	}

	signer, ok := pk.(crypto.Signer)
	if !ok {
		glog.Errorf("ERROR:  error creating crypto.signer from privatekey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error creating crypto.signer from privatekey"))
	}

	h := sha256.New()
	h.Write(in.Data)
	digest := h.Sum(nil)

	sig, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		glog.Errorf("ERROR:  error signing %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error signing"))
	}

	return &verifier.SignResponse{
		Signed: sig,
	}, nil
}

func (s *server) StartTLS(ctx context.Context, in *verifier.StartTLSRequest) (*verifier.StartTLSResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= StartTLS ========")

	if s.running {
		return &verifier.StartTLSResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   Server already running"))
	}

	go func() error {

		router := mux.NewRouter()
		router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

		config := &attest.OpenConfig{
			TPMVersion: attest.TPMVersion20,
		}
		tpm, err := attest.OpenTPM(config)
		if err != nil {
			glog.Errorf("ERROR:  opening tpm %v", err)
			return fmt.Errorf("ERROR:  could not get TPM")
		}
		defer tpm.Close()

		_, err = os.Stat(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
		if err != nil {
			glog.Errorf("ERROR:  cannot Sign without signing key Key; first run GetAK then NewKey %v", err)
			return fmt.Errorf("ERROR:    cannot Sign without signing key Key; first run GetAK then NewKey ")
		}

		skBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
		if err != nil {
			glog.Errorf("ERROR:  error reading sigining key file at path %v", err)
			return fmt.Errorf("ERROR:   error reading signing file at path")
		}

		sk, err := tpm.LoadKey(skBytes)
		if err != nil {
			glog.Errorf("ERROR:  error loading signing key %v", err)
			return fmt.Errorf("ERROR:  error loading signing key")
		}
		defer sk.Close()

		signer, err = sk.Private(sk.Public())
		if err != nil {
			glog.Errorf("  error loading signer %v", err)
			return fmt.Errorf("ERROR:  error loading signer %v", err)
		}

		glog.V(2).Infof("        Issuing Selfsigned Cert ========")

		var notBefore time.Time
		notBefore = time.Now()

		notAfter := notBefore.Add(time.Hour * 24 * 365)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			glog.Errorf("ERROR: Failed to generate serial number: %v", err)
			return fmt.Errorf("ERROR:  Failed to generate serial number:")
		}

		issuerCertBytes, err := ioutil.ReadFile(*issuerCert)
		if err != nil {
			glog.Errorf("Error Reading root ca %v", err)
			return fmt.Errorf("Error Reading root ca %v", err)
		}

		rcblock, _ := pem.Decode(issuerCertBytes)

		rcert, err := x509.ParseCertificate(rcblock.Bytes)
		if err != nil {
			glog.Errorf("ERROR:  error loading issuerkey %v", err)
			return fmt.Errorf("ERROR:  error loading issuerkey")
		}
		issuerKeyBytes, err := ioutil.ReadFile(*issuerKey)
		if err != nil {
			glog.Errorf("ERROR:  error loading issuerkey %v", err)
			return fmt.Errorf("ERROR:  error loading issuerkey")
		}
		rblock, _ := pem.Decode(issuerKeyBytes)
		r, err := x509.ParsePKCS8PrivateKey(rblock.Bytes)
		if err != nil {
			glog.Errorf("ERROR:  error loading privatekey %v", err)
			return fmt.Errorf("ERROR:  error loading signing privatekey")
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization:       []string{"Acme Co"},
				OrganizationalUnit: []string{"Enterprise"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
				CommonName:         "foo",
			},
			DNSNames:              []string{"echo.esodemoapp2.com"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, rcert, sk.Public(), r)
		if err != nil {
			glog.Errorf("ERROR:  Failed to create certificate: %s\n", err)
			return fmt.Errorf("ERROR:  Failed to create certificate: %s\n", err)
		}

		p, err := x509.ParseCertificate(derBytes)
		if err != nil {
			glog.Errorf("ERROR:  Failed to  parse certificate: %s", err)
			fmt.Errorf("ERROR:  Failed to  parse certificate: %s", err)
		}
		glog.V(2).Infof("cert Issuer %s\n", p.Issuer)
		c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		glog.V(2).Infof("        Issued Certificate ========\n%s\n", c)

		pubkey_bytes, err := x509.MarshalPKIXPublicKey(p.PublicKey)
		if err != nil {
			glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
			return fmt.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
		}
		kpem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PUBLIC KEY",
				Bytes: pubkey_bytes,
			},
		)

		if err := os.WriteFile(fmt.Sprintf("%s/%s.%s-tls.crt", *contextsPath, in.Uid, in.Kid), c, 0600); err != nil {
			glog.Errorf("ERROR:  could not write ak to file %v", err)
			return fmt.Errorf("ERROR:  writing cert to file")
		}

		glog.V(2).Infof("        Issued certificate tied to PubicKey ========\n%s\n", kpem)

		tlsCrt := tls.Certificate{
			Certificate: [][]byte{p.Raw},
			Leaf:        p,
			PrivateKey:  signer,
		}

		var server *http.Server
		server = &http.Server{
			Addr:    *applicationPort,
			Handler: router,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCrt},
			},
		}

		http2.ConfigureServer(server, &http2.Server{})
		glog.V(2).Infof("Starting Server..")

		s.running = true
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			glog.Errorf("        Error Listening \n%v\n", err)
			return fmt.Errorf("ERROR: listening: %v", err)
		}
		return nil

	}()

	return &verifier.StartTLSResponse{
		Status: true,
	}, nil

}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(10).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}
	if err := rwc.Close(); err != nil {
		glog.Fatalf("can't close TPM %q: %v", tpmDevice, err)
	}
	glog.V(2).Info("Getting EKCert reset")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Fatalf("error opening TPM %v", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		glog.Fatalf("error getting EK %v", err)
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("ECCert with available Issuer: %s", e.Certificate.Issuer)
		}
	}

	ek = eks[0]

	defaultCerts, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		glog.Fatalf("failed to create default certs: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{defaultCerts},
	}
	ce := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)
	mrnd.Seed(time.Now().UnixNano())
	s.Serve(lis)
}
