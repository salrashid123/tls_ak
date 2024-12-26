package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"slices"
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
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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
	encodingPCR     = flag.Uint("encodingPCR", 0, "PCR to extend with TLS public key hash")
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
)

const ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type server struct {
	mu      sync.Mutex
	running bool
}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	p, ok := peer.FromContext(ctx)
	if ok {
		peerIPPort, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not get Remote IP   %v", err))
		}
		glog.V(20).Infof("     Connected from peer %v", peerIPPort)
	} else {
		glog.Errorf("ERROR:  Could not extract peerInfo from TLS")
		return nil, status.Errorf(codes.PermissionDenied, "ERROR:  Could not extract peerInfo from TLS")
	}
	return handler(ctx, req)
}

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
	EKM              string
	PeerIP           string
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

	if ekCert != nil {
		return &verifier.GetEKResponse{
			EkPub:  ekpubBytes,
			EkCert: ekCert.Raw,
		}, nil
	}
	return &verifier.GetEKResponse{
		EkPub: ekpubBytes,
	}, nil

}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetAK ========")

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
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	glog.V(2).Info("Getting EKCert")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err = attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("error opening TPM %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		glog.Errorf("error getting EK %v", err)
		os.Exit(1)
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("ECCert with available Issuer: %s", e.Certificate.Issuer)
		}
	}

	if len(eks) == 0 {
		glog.Error("error no EK found")
		os.Exit(1)
	}

	// use the  ek at 0 for now...
	ek = &eks[0]

	if ek.Public == nil {
		glog.Error("error no Public not found")
		os.Exit(1)
	}

	ekpubBytes, err = x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		glog.Errorf("ERROR:  could  marshall public key %v", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	akbytes, err = ak.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could marshall AK %v", err)
		os.Exit(1)
	}

	// now crate the TLS EC key on the TPM
	kConfig := &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
	}
	nk, err := tpm.NewKey(ak, kConfig)
	if err != nil {
		glog.Errorf("ERROR:  error creating key  %v", err)
		os.Exit(1)
	}
	err = ak.Close(tpm)
	if err != nil {
		glog.Errorf("ERROR:  error closing ak  %v", err)
		os.Exit(1)
	}

	nkBytes, err = nk.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could not marshall newkey %v", err)
		os.Exit(1)
	}

	pubKey, ok := nk.Public().(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("Could not assert the public key to ec public key")
		os.Exit(1)
	}

	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("Could not MarshalPKIXPublicKey ec public key")
		os.Exit(1)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeybytes,
		},
	)

	glog.V(2).Infof("Generated ECC Public %s", string(pubkeyPem))

	// if the *encodingPCR is set to non zero, then reset
	//   that PCR bank  and extend it with the hash of the TLS Public key
	//   the client can compare the PCR bank's value after quote/verify to
	//   with the hash of the tls cert
	if *encodingPCR != 0 {

		hasher := sha256.New()
		_, err := hasher.Write(pubkeybytes)
		if err != nil {
			glog.Errorf("ERROR:  hashing public cert %v", err)
			os.Exit(1)
		}
		tlsCertificateHash := hasher.Sum(nil)
		glog.V(2).Infof("Generated ECC Public Hash %s", base64.StdEncoding.EncodeToString((tlsCertificateHash)))

		rwc, err := openTPM(*tpmDevice)
		if err != nil {
			glog.Errorf("ERROR:  open TPM %v", err)
			os.Exit(1)
		}
		defer func() {
			rwc.Close()
		}()

		rwr := transport.FromReadWriter(rwc)

		pcrReadRsp, err := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(*encodingPCR),
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			glog.Errorf("ERROR:  could not get AK %v", err)
			os.Exit(1)
		}

		for _, d := range pcrReadRsp.PCRValues.Digests {
			glog.V(10).Infof("        Current Digest:   %s\n", hex.EncodeToString(d.Buffer))
		}
		glog.V(10).Infof("        Resetting Digest")
		_, err = tpm2.PCRReset{
			PCRHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(*encodingPCR),
				Auth:   tpm2.PasswordAuth(nil),
			},
		}.Execute(rwr)
		if err != nil {
			glog.Errorf("ERROR:  could not reset PCR %v", err)
			os.Exit(1)
		}

		_, err = tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(uint32(*encodingPCR)),
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digests: tpm2.TPMLDigestValues{
				Digests: []tpm2.TPMTHA{
					{
						HashAlg: tpm2.TPMAlgSHA256,
						Digest:  tlsCertificateHash,
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			glog.Errorf("ERROR:  could extend %v", err)
			os.Exit(1)
		}

		pcrReadRspExtended, err := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(*encodingPCR),
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			glog.Errorf("ERROR:  could not read PCR %v", err)
			os.Exit(1)
		}

		for _, d := range pcrReadRspExtended.PCRValues.Digests {
			glog.V(10).Infof("        Extended Digest:   %s\n", hex.EncodeToString(d.Buffer))
		}

		err = rwc.Close()
		if err != nil {
			glog.Errorf("ERROR:  error closing tpm %v", err)
			os.Exit(1)
		}
	}

	// **********************************************************

	// extract the crypto.Signer from the TLS key

	signer, err := nk.Private(nk.Public())
	if err != nil {
		glog.Errorf("ERROR: getting crypto.Signer from generated key %v", err)
		os.Exit(1)
	}

	// generate a CSR
	glog.V(10).Infof("        Issuing Cert ========")

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24) // valid for a day

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		glog.Errorf("ERROR: Failed to generate serial number: %v", err)
		os.Exit(1)
	}

	issuerCertBytes, err := os.ReadFile(*issuerCert)
	if err != nil {
		glog.Errorf("Error Reading root ca %v", err)
		os.Exit(1)
	}

	rcblock, _ := pem.Decode(issuerCertBytes)

	rcert, err := x509.ParseCertificate(rcblock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading issuercertificate %v", err)
		os.Exit(1)
	}
	issuerKeyBytes, err := os.ReadFile(*issuerKey)
	if err != nil {
		glog.Errorf("ERROR:  error loading issuerkey %v", err)
		os.Exit(1)
	}
	rblock, _ := pem.Decode(issuerKeyBytes)
	r, err := x509.ParsePKCS8PrivateKey(rblock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading privatekey %v", err)
		os.Exit(1)
	}

	// simulate creating a CSR to send to some CA
	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "foo",
		},
		DNSNames:           []string{*httpServerName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// create the CSR but note the private key is the EC keys's "signer"
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, signer)
	if err != nil {
		glog.Errorf("ERROR:  error creating csr %v", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	// now use certain fields within the CSR and the overall template to issue the cert on the CA
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         clientCSR.Subject.CommonName, // from CSR
		},
		DNSNames:              clientCSR.DNSNames, // from CSR
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// now issue the cert using the local CA
	issuedTLSderBytes, err = x509.CreateCertificate(rand.Reader, &template, rcert, clientCSR.PublicKey, r)
	if err != nil {
		glog.Errorf("ERROR:  Failed to create certificate: %s\n", err)
		os.Exit(1)
	}

	p, err := x509.ParseCertificate(issuedTLSderBytes)
	if err != nil {
		glog.Errorf("ERROR:  Failed to  parse certificate: %s", err)
		os.Exit(1)
	}
	glog.V(10).Infof("        cert Issuer %s\n", p.Issuer)

	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuedTLSderBytes})
	glog.V(10).Infof("        Issued Certificate ========\n%s\n", c)

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(p.PublicKey)
	if err != nil {
		glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
		os.Exit(1)
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
		Certificate: [][]byte{p.Raw},
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
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{defaultCerts},
	}
	ce := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Errorf("failed to listen: %v", err)
		os.Exit(1)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)
	s.Serve(lis)
}
