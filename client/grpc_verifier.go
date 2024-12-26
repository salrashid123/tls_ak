package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/uuid"

	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"

	"github.com/google/go-tpm/legacy/tpm2"
	certparser "github.com/salrashid123/gcp-tpm/parser"
	"github.com/salrashid123/tls_ak/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	address              = flag.String("host", "localhost:50051", "host:port of gRPC server")
	appaddress           = flag.String("appaddress", "localhost:8081", "host:port of gRPC server")
	tlsCert              = flag.String("tlsCert", "certs/ca.crt", "tls Certificate")
	dynamicCaCert        = flag.String("dynamicCaCert", "certs/issuer_ca.crt", "tls Certificate for dynamic issuer")
	grpcServerName       = flag.String("grpcservername", "attestor.domain.com", "SNI for grpc server")
	httpServerName       = flag.String("httpservername", "echo.domain.com", "SNI for http server")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")
	encodingPCR          = flag.Uint("encodingPCR", 0, "PCR to extend with TLS public key hash")
	ekRootCA             = flag.String("ekrootCA", "certs/ek_root.pem", "EK rootsCA")
	ekIntermediateCA     = flag.String("ekintermediateCA", "certs/ek_intermediate.pem", "EK intermediate CA")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
	var err error

	var tlsCfg tls.Config
	rootCAs := x509.NewCertPool()
	ca_pem, err := os.ReadFile(*tlsCert)
	if err != nil {
		glog.Errorf("failed to load root CA certificates  error=%v", err)
		os.Exit(1)
	}
	if !rootCAs.AppendCertsFromPEM(ca_pem) {
		glog.Errorf("no root CA certs parsed from file ")
		os.Exit(1)
	}
	tlsCfg.RootCAs = rootCAs
	tlsCfg.ServerName = *grpcServerName

	ce := credentials.NewTLS(&tlsCfg)
	ctx := context.Background()

	// first connect to the GRPC service using default TLS certs
	//conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// get the ekpublic key and if available, the ekcert
	glog.V(5).Infof("=============== start GetEK ===============")

	ekReq := &verifier.GetEKRequest{}

	c := verifier.NewVerifierClient(conn)
	ekResponse, err := c.GetEK(ctx, ekReq)
	if err != nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	// first try to verify the ekcert (if available)
	// only GCE confidential vm's have ekCerts https://github.com/salrashid123/gcp-vtpm-ek-ak
	// the following root and intermediates are for GCE confidential VMs
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.encryptionKey.ekCert' > ekcert.pem
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.signingKey.ekCert' > akcert.pem
	// $ wget http://privateca-content-633beb94-0000-25c1-a9d7-001a114ba6e8.storage.googleapis.com/c59a22589ab43a57e3a4/ca.crt -O ek_intermediate.crt
	// $ wget http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt -O ek_root.crt
	// $ openssl x509 -inform der -in ek_intermediate.crt -out ek_intermediate.pem
	// $ openssl x509 -inform der -in ek_root.crt -out ek_root.pem
	var ekPubPEM []byte
	if len(ekResponse.EkCert) > 0 {
		ekcert, err := x509.ParseCertificate(ekResponse.EkCert)
		if err != nil {
			glog.Errorf("ERROR:   ParseCertificate: %v", err)
			os.Exit(1)
		}

		c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekResponse.EkCert})
		glog.V(2).Infof("        EKCertificate ========\n%s\n", c)

		spubKey := ekcert.PublicKey.(*rsa.PublicKey)

		skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
		if err != nil {
			glog.Errorf("ERROR:  could  MarshalPKIXPublicKey: %v", err)
			os.Exit(1)
		}
		ekPubPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: skBytes,
			},
		)

		glog.V(10).Infof("     EKCert  Issuer %v", ekcert.Issuer)
		glog.V(10).Infof("     EKCert  IssuingCertificateURL %v", fmt.Sprint(ekcert.IssuingCertificateURL))

		// if the service is on GCP, the ekcerts has some special details encoded inside it
		gceInfo, err := server.GetGCEInstanceInfo(ekcert)
		if err == nil && gceInfo != nil {
			glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
			glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
			glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
		}

		glog.V(40).Infof("    EkCert Public Key \n%s\n", ekPubPEM)

		// now try to verify the EKCert is legit using the CA's you expect woud've signed it
		glog.V(10).Info("    Verifying EKCert")
		rootPEM, err := os.ReadFile(*ekRootCA)
		if err != nil {
			glog.Errorf("failed to reading roots: ", err.Error())
			os.Exit(1)
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(rootPEM))
		if !ok {
			glog.Errorf("failed append to roots ")
			os.Exit(1)
		}

		var exts []asn1.ObjectIdentifier
		for _, ext := range ekcert.UnhandledCriticalExtensions {
			if ext.Equal(certparser.OidExtensionSubjectAltName) {
				continue
			}
			exts = append(exts, ext)
		}
		ekcert.UnhandledCriticalExtensions = exts

		intermediatePEM, err := os.ReadFile(*ekIntermediateCA)
		if err != nil {
			glog.Errorf("failed to read intermediate CA: " + err.Error())
			os.Exit(1)
		}

		intermediates := x509.NewCertPool()
		ok = intermediates.AppendCertsFromPEM([]byte(intermediatePEM))
		if !ok {
			glog.Errorf("failed to append intermediates: ")
			os.Exit(1)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
		}
		if _, err := ekcert.Verify(opts); err != nil {
			glog.Errorf("failed to verify certificate: " + err.Error())
			os.Exit(1)
		}

		glog.V(10).Info("    EKCert Verified")
	} else {
		ekPubPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: ekResponse.EkPub,
			},
		)
	}

	glog.V(5).Infof("     EKPub: \n%s\n", ekPubPEM)

	spkiBlock, _ := pem.Decode(ekPubPEM)

	ekPubKey, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  could  parsing ek public key %v", err)
		os.Exit(1)
	}

	bblock, _ := pem.Decode(ekPubPEM)
	if bblock == nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("=============== end GetEKCert ===============")

	// now get the attestation key
	glog.V(5).Infof("=============== start GetAK ===============")
	akResponse, err := c.GetAK(ctx, &verifier.GetAKRequest{})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	serverAttestationParameter := &attest.AttestationParameters{}
	reader := bytes.NewReader(akResponse.AttestationParameters)
	err = json.NewDecoder(reader).Decode(serverAttestationParameter)
	if err != nil {
		glog.Errorf("Error encoding serverAttestationParamer %v", err)
		os.Exit(1)
	}

	akp, err := attest.ParseAKPublic(attest.TPMVersion20, serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Error Parsing AK %v", err)
		os.Exit(1)
	}

	akpPub, err := x509.MarshalPKIXPublicKey(akp.Public)
	if err != nil {
		glog.Errorf("Error MarshalPKIXPublicKey ak %v", err)
		os.Exit(1)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akpPub,
		},
	)

	glog.V(5).Infof("      ak public \n%s\n", akPubPEM)
	glog.V(5).Infof("=============== end GetAK ===============")

	// do remote attestation usign the ek and ak
	glog.V(5).Infof("=============== start Attest ===============")

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekPubKey,
		AK:         *serverAttestationParameter,
	}

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		glog.Errorf("Error generating make credential parameters %v", err)
		os.Exit(1)
	}
	glog.Infof("      Outbound Secret: %s\n", base64.StdEncoding.EncodeToString(secret))

	encryptedCredentialsBytes := new(bytes.Buffer)
	err = json.NewEncoder(encryptedCredentialsBytes).Encode(encryptedCredentials)
	if err != nil {
		glog.Errorf("Error encoding encryptedCredentials %v", err)
		os.Exit(1)
	}

	mcResponse, err := c.Attest(ctx, &verifier.AttestRequest{
		EncryptedCredentials: encryptedCredentialsBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("      Inbound Secret: %s\n", base64.StdEncoding.EncodeToString(mcResponse.Secret))

	if base64.StdEncoding.EncodeToString(mcResponse.Secret) == base64.StdEncoding.EncodeToString(secret) {
		glog.V(5).Infof("      inbound/outbound Secrets Match; accepting AK")
	} else {
		glog.Error("attestation secrets do not match; exiting")
		os.Exit(1)
	}
	glog.V(5).Infof("=============== end Attest ===============")

	// run a quote-verify operation
	glog.V(5).Infof("=============== start Quote/Verify ===============")

	nonce := []byte(uuid.New().String())
	quoteResponse, err := c.Quote(ctx, &verifier.QuoteRequest{
		Nonce: nonce,
	})
	if err != nil {
		glog.Errorf("Quote Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	// create pcr map for go-tpm-tools
	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		glog.Errorf("  Could not get PCRMap: %s", err)
		os.Exit(1)
	}
	//vpcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	serverPlatformAttestationParameter := &attest.PlatformParameters{}
	err = json.NewDecoder(bytes.NewReader(quoteResponse.PlatformAttestation)).Decode(serverPlatformAttestationParameter)
	if err != nil {
		glog.Errorf("Quote Failed: json decoding quote response: %v", err)
		os.Exit(1)
	}

	pub, err := attest.ParseAKPublic(attest.TPMVersion20, serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Quote Failed ParseAKPublic: %v", err)
		os.Exit(1)
	}

	// compare the ak provided earlier during attestation with the one bound to the quote; they must be the same
	qakBytes, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		glog.Errorf("Error %v", err)
		os.Exit(1)
	}
	qakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: qakBytes,
		},
	)

	glog.V(5).Infof("      quote-attested public \n%s\n", qakPubPEM)

	if base64.StdEncoding.EncodeToString(qakPubPEM) != base64.StdEncoding.EncodeToString(akPubPEM) {
		glog.Errorf("Attested key does not match value in quote")
		os.Exit(1)
	}

	for _, quote := range serverPlatformAttestationParameter.Quotes {
		if err := pub.Verify(quote, serverPlatformAttestationParameter.PCRs, nonce); err != nil {
			glog.Errorf("Quote Failed Verify: %v", err)
			os.Exit(1)
		}
	}

	var encodingPCRValue []byte
	for _, p := range serverPlatformAttestationParameter.PCRs {
		glog.V(20).Infof("     PCR: %d, verified: %t value: %s", p.Index, p.QuoteVerified(), hex.EncodeToString((p.Digest)))
		if p.DigestAlg == crypto.SHA256 {
			v, ok := pcrMap[uint32(p.Index)]
			if ok {
				if hex.EncodeToString(v) != hex.EncodeToString(p.Digest) {
					glog.Errorf("Quote Failed Verify for index: %d", p.Index)
					os.Exit(1)
				}
			}
			// now stash pcr23's value, this is the bank where the value was extended with the certificates fingerprint
			if p.Index == int(*encodingPCR) {
				encodingPCRValue = p.Digest
			}
		}
	}

	glog.V(5).Infof("     quotes verified")
	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	for _, e := range el.Events(attest.HashSHA256) {
		glog.V(60).Infof("Event Index: %d", e.Index)
		glog.V(60).Infof("   Event Type: %s", e.Type)
		glog.V(60).Infof("   Event: %s", string(e.Data))
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA1))
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     secureBoot State enabled %t", sb.Enabled)

	if _, err := el.Verify(serverPlatformAttestationParameter.PCRs); err != nil {
		glog.Errorf("Quote Verify Failed: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("=============== end Quote/Verify ===============")

	// now ask the server for the EC TLS key
	glog.V(5).Infof("=============== start NewKey ===============")

	kid := uuid.New().String()
	newKeyResponse, err := c.GetTLSKey(ctx, &verifier.GetAttestedKeyRequest{
		Kid: kid,
	})
	if err != nil {
		glog.Errorf("newKey Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	cr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newKeyResponse.Certificate})
	glog.V(2).Infof("        TLSCertificate ========\n%s\n", cr)

	remoteTLScert, err := x509.ParseCertificate(newKeyResponse.Certificate)
	if err != nil {
		glog.Errorf("error parsing tls certificate  %v", err)
		os.Exit(1)
	}

	// verify the tls key is certified by the AK
	keyCertificationParameter := &attest.CertificationParameters{}
	err = json.NewDecoder(bytes.NewReader(newKeyResponse.KeyCertification)).Decode(keyCertificationParameter)
	if err != nil {
		glog.Errorf("Key Certification  %v", err)
		os.Exit(1)
	}

	err = keyCertificationParameter.Verify(attest.VerifyOpts{
		Public: akp.Public,
		Hash:   crypto.SHA256,
	})
	if err != nil {
		glog.Errorf("Key Verification error %v", err)
		os.Exit(1)
	}

	decodedTPMNTPublic, err := tpm2.DecodePublic(keyCertificationParameter.Public)
	if err != nil {
		glog.Errorf("error parsing TPM public key structure: %v", err)
		os.Exit(1)
	}

	tlsPubKey, err := decodedTPMNTPublic.Key()
	if err != nil {
		glog.Errorf("error parsing getting public key for TLS Key: %v", err)
		os.Exit(1)
	}
	tlsECCPub, ok := tlsPubKey.(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("error converting tls public key to ec key: %v", err)
		os.Exit(1)
	}

	// certifyPubbytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
	// if err != nil {
	// 	glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
	// 	os.Exit(1)
	// }
	// certifyPEM := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "PUBLIC KEY",
	// 		Bytes: certifyPubbytes,
	// 	},
	// )

	if tlsECCPub.Equal(remoteTLScert.PublicKey) {
		glog.V(5).Info("     certified public key matches public key in x509 certificate")
	} else {
		glog.Errorf("ERROR:  certified public key does not matches public key in x509 certificate")
		os.Exit(1)
	}

	if *encodingPCR != 0 {
		// By convention, the server reset PCR bank *encodingPCR (eg, pcr=23) to zeros
		//  after that, it extended the pcr value using the hash of the issued TLS x509 certificate.
		//  what the following does is hashes the certificate
		//  then prepends the null pcr value (zeros) to the cert's hash, then hashes all that
		//  what your'e basically left with a value which should match what the server sent down as
		//  the value for *encodingPCR
		pubkeybytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
		if err != nil {
			glog.Errorf("Could not MarshalPKIXPublicKey ec public key")
			os.Exit(1)
		}

		khasher := sha256.New()
		khasher.Write(pubkeybytes)
		tlsCertificateHash := khasher.Sum(nil)

		phasher := sha256.New()
		pcrEmpty, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			glog.Errorf("Could create empty pcr value")
			os.Exit(1)
		}
		cb := append(pcrEmpty, tlsCertificateHash...)
		phasher.Write(cb)
		pcrHash := phasher.Sum(nil)

		glog.V(30).Infof("     TLS ECC Public Hash %s", hex.EncodeToString((tlsCertificateHash)))
		glog.V(30).Infof("     Encoding PCR Value Public Hash %s", hex.EncodeToString((encodingPCRValue)))
		glog.V(30).Infof("     Calculated PCR Value  %s", hex.EncodeToString((pcrHash)))

		if hex.EncodeToString((encodingPCRValue)) != hex.EncodeToString((pcrHash)) {
			glog.Errorf("hash of pcr=[%d] incorrect, got [%s], expected [%s]", *encodingPCR, hex.EncodeToString((encodingPCRValue)), hex.EncodeToString((pcrHash)))
			os.Exit(1)
		}
	}
	glog.V(5).Infof("     TLS key verified")
	glog.V(5).Infof("=============== end NewKey ===============")

	// now that we trust the TLS key, connect  over HTTPS
	glog.V(5).Infof("=============== start http client ===============")

	rootPEM, err := os.ReadFile(*dynamicCaCert)
	if err != nil {
		glog.Errorf("Error Reading root %v", err)
		os.Exit(1)
	}

	roots := x509.NewCertPool()
	ok = roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		glog.Errorf("failed to parse root certificate")
		os.Exit(1)
	}

	dynamicTLSConfig := &tls.Config{
		RootCAs:    roots,
		ServerName: *httpServerName,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			glog.V(20).Infof("VerifiedChains")
			for _, cert := range verifiedChains {
				for i, c := range cert {
					glog.V(20).Infof("      %d Subject %s\n", i, c.Subject)
					glog.V(20).Infof("      %d Issuer Name: %s\n", i, c.Issuer)
					glog.V(20).Infof("      %d Expiry: %s \n", i, c.NotAfter.Format("2006-January-02"))
					glog.V(20).Infof("      %d Issuer Common Name: %s \n", i, c.Issuer.CommonName)
					glog.V(20).Infof("      %d IsCA: %t \n", i, c.IsCA)
					h := sha256.New()
					h.Write(c.Raw)
					clientCertificateHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

					glog.V(20).Infof("      %d Certificate hash %s\n", i, clientCertificateHash)
				}
			}
			return nil
		},
	}

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, dynamicTLSConfig)
			if err != nil {
				return conn, err
			}
			err = conn.Handshake()
			if err != nil {
				return conn, err
			}
			cs := conn.ConnectionState()
			ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
			if err != nil {
				return nil, fmt.Errorf("exportKeyingMaterial failed: %v", err)
			}
			glog.V(30).Infof("  EKM my_nonce: %s\n", hex.EncodeToString(ekm))

			// extract the peer certificate.
			// this is the EC key and local ca-signed cert
			if len(cs.PeerCertificates) == 0 {
				return nil, fmt.Errorf("peer certificate not found")
			}
			derBytes := cs.PeerCertificates[0].Raw
			p, err := x509.ParseCertificate(derBytes)
			if err != nil {
				return nil, fmt.Errorf("ERROR:  Failed to  parse certificate: %s", err)
			}
			glog.V(2).Infof("      Issuer %s\n", p.Issuer)

			// extract its public key, this is the EC key
			pubkey_bytes, err := x509.MarshalPKIXPublicKey(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return nil, fmt.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
			}
			kpem := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkey_bytes,
				},
			)
			glog.V(5).Infof("       peer public key \n%s\n", kpem)

			peerPubKey, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("error converting peer tls public key to ec key: %v", err)
			}
			// compare the peer key with the one that was certified

			decodedTPMNTPublic, err := tpm2.DecodePublic(keyCertificationParameter.Public)
			if err != nil {
				return nil, fmt.Errorf("error parsing TPM public key structure: %v", err)
			}

			tlsPubKey, err := decodedTPMNTPublic.Key()
			if err != nil {
				return nil, fmt.Errorf("error parsing getting public key for TLS Key: %v", err)
			}
			tlsECCPub, ok := tlsPubKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("error converting tls public key to ec key: %v", err)
			}

			certifyPubbytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
			if err != nil {
				return nil, fmt.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
			}
			certifyPEM := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: certifyPubbytes,
				},
			)
			glog.V(5).Infof("       certified public key \n%s\n", certifyPEM)

			if tlsECCPub.Equal(peerPubKey) && tlsECCPub.Equal(remoteTLScert.PublicKey) {
				glog.V(5).Info("     peer tls public key matched attested key")
			} else {
				return nil, fmt.Errorf("ERROR:  peer public keys mismatch  expected \n[%s]\n\ngot: \n[%s]", certifyPEM, kpem)
			}

			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip := net.ParseIP(host)
			glog.V(10).Infof("     Connected to IP: %s\n", ip)
			return conn, nil
		},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s", *appaddress))
	if err != nil {
		glog.Errorf("Error Reading new host %v", err)
		os.Exit(1)
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Error calling new dynamic host %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	glog.V(5).Infof("%v\n", resp.Status)
	glog.V(5).Infof(string(htmlData))

}

func getPCRMap(algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(*expectedPCRMapSHA256, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}
