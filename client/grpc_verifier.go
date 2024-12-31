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
	certparser "github.com/salrashid123/gcp-vtpm-ek-ak/parser"
	"github.com/salrashid123/tls_ak/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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
	ekRootCA             = flag.String("ekrootCA", "certs/ek_root.pem", "EK rootsCA")
	ekIntermediateCA     = flag.String("ekintermediateCA", "certs/ek_intermediate.pem", "EK intermediate CA")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
	var err error

	grpcRootCAs := x509.NewCertPool()
	ca_pem, err := os.ReadFile(*tlsCert)
	if err != nil {
		glog.Errorf("failed to load root CA certificates  error=%v", err)
		os.Exit(1)
	}
	if !grpcRootCAs.AppendCertsFromPEM(ca_pem) {
		glog.Errorf("no root CA certs parsed from file ")
		os.Exit(1)
	}
	tlsCfg := tls.Config{
		RootCAs:    grpcRootCAs,
		ServerName: *grpcServerName,
	}

	ce := credentials.NewTLS(&tlsCfg)
	ctx := context.Background()

	// first connect to the GRPC service using default TLS certs
	//conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// get the EKCert;  you can also 'just read' it from certs/ekcert.epm
	//  if you downloaded it earlier and trust it; its verified later against roots.
	glog.V(5).Infof("=============== start GetEK ===============")

	ekReq := &verifier.GetEKRequest{}

	c := verifier.NewVerifierClient(conn)

	pr := new(peer.Peer)
	ekResponse, err := c.GetEK(ctx, ekReq, grpc.Peer(pr))
	if err != nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		authType := info.AuthType()
		sn := info.State.ServerName
		glog.V(20).Infof("        AuthType, ServerName %s, %s\n", authType, sn)
		tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
		if !ok {
			glog.Errorf("ERROR:  Could get remote TLS")
			os.Exit(1)
		}
		ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			glog.Errorf("ERROR:  Could getting EKM %v", err)
			os.Exit(1)
		}
		glog.V(20).Infof("        EKM my_nonce: %s\n", hex.EncodeToString(ekm))
	default:
		glog.Errorf("Unknown AuthInfo type")
		os.Exit(1)
	}

	// first try to verify the ekcert
	// Note: GCE confidential vm's have ekCerts https://github.com/salrashid123/gcp-vtpm-ek-ak which you can get via API
	// the following root and intermediates are for GCE confidential VMs
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.encryptionKey.ekCert' > certs/ekcert.pem
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.signingKey.ekCert' > certs/akcert.pem
	// $ curl -s $(openssl x509 -in certs/ekcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_intermediate.pem
	// $ curl -s $(openssl x509 -in certs/ek_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_root.pem
	//
	// for other TPMs,  you can get the EK on the TPM itself and verify against the manufacturers CA
	//  see https://github.com/salrashid123/tls_ak?tab=readme-ov-file#local-testing
	//
	var ekPubPEM []byte

	ekcert, err := x509.ParseCertificate(ekResponse.EkCert)
	if err != nil {
		glog.Errorf("ERROR:   ParseCertificate: %v", err)
		os.Exit(1)
	}

	ekcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekResponse.EkCert})
	glog.V(2).Infof("        EKCertificate ========\n%s\n", ekcrtPEM)

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

	// if the service is on GCP, the ekcert has some special details encoded inside it
	gceInfo, err := server.GetGCEInstanceInfo(ekcert)
	if err == nil && gceInfo != nil {
		glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
		glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
		glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
	}

	glog.V(40).Infof("    EkCert Public Key \n%s\n", ekPubPEM)

	// now try to verify the EKCert is legit using the CA's you expect woud've signed it
	glog.V(10).Info("    Verifying EKCert")
	ekRootPEM, err := os.ReadFile(*ekRootCA)
	if err != nil {
		glog.Errorf("failed to reading roots: ", err.Error())
		os.Exit(1)
	}

	ekRoots := x509.NewCertPool()
	ok := ekRoots.AppendCertsFromPEM([]byte(ekRootPEM))
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

	//oid 2.23.133.8.1 tcg-kp-EKCertificate Identifies the certificate as an Endorsement Credential.
	// try to see if the ekcert includes the recommended oid as the extension value
	var tcgkpEKCertificate asn1.ObjectIdentifier = []int{2, 23, 133, 8, 1}
	for _, ku := range ekcert.UnknownExtKeyUsage {
		if ku.Equal(tcgkpEKCertificate) {
			glog.V(10).Infof("     EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage %s", ku.String())
		}
	}

	// optionally parse SAN.DirName, eg:
	// pg 24: https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
	// X509v3 Subject Alternative Name: critical
	//   DirName:/2.23.133.2.1=id:53544D20/2.23.133.2.2=ST33HTPHAHD8/2.23.133.2.3=id:00010102
	// 2.23.133.2.1 tcg-at-tpmManufacturer TPM Manufacturer Name for EK Credential Profile for TPM 2.0
	//     id:53544D20 https://github.com/cedarcode/tpm-key_attestation/blob/master/lib/tpm/constants.rb#L41
	// 2.23.133.2.2 tcg-at-tpmModel TPM Model Number defined in EK Credential Profile for TPM 2.0
	// 2.23.133.2.3 tcg-at-tpmVersion TPM Version defined in EK Credential Profile for TPM 2.0

	// todo, understand why the following works...

	// var sanOID asn1.ObjectIdentifier = []int{2, 5, 29, 17}
	// for _, san := range ekcert.Extensions {
	// 	if san.Id.Equal(sanOID) {
	// 		glog.V(20).Infof("     EKCert SAN DirName: %s", san.Value)
	// 		var seq asn1.RawValue
	// 		var err error
	// 		_, err = asn1.Unmarshal(san.Value, &seq)
	// 		if err != nil {
	// 			glog.Errorf("failed to unmarshal sequence " + err.Error())
	// 			os.Exit(1)
	// 		}

	// 		var v asn1.RawValue
	// 		_, err = asn1.Unmarshal(seq.Bytes, &v)
	// 		if err != nil {
	// 			glog.Errorf("failed to unmarshal sequenceBytes: " + err.Error())
	// 			os.Exit(1)
	// 		}

	// 		var rdnSeq pkix.RDNSequence
	// 		if _, err := asn1.Unmarshal(v.Bytes, &rdnSeq); err != nil {
	// 			glog.Errorf("failed to Unmarshal name: " + err.Error())
	// 			os.Exit(1)
	// 		}
	// 		var dirName pkix.Name
	// 		dirName.FillFromRDNSequence(&rdnSeq)

	// 		for _, n := range dirName.Names {
	// 			glog.V(20).Infof("     DirName %s: %s", n.Type.String(), n.Value)
	// 		}
	// 	}
	// }

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
		Roots:         ekRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := ekcert.Verify(opts); err != nil {
		glog.Errorf("failed to verify certificate: " + err.Error())
		os.Exit(1)
	}

	glog.V(10).Info("    EKCert Verified")

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
		// determine if SEV is enabled on GCE:
		//  see https://gist.github.com/salrashid123/0c7a4a6f7465cff19d05ac50d238cd57
		// if e.Index == 0 && e.Type.String() == "EV_NONHOST_INFO" {
		// 	sevStatus, err := server.ParseGCENonHostInfo(e.Data)
		// 	if err != nil {
		// 		glog.Errorf("Error parsing SEV Status: %v", err)
		// 		os.Exit(1)
		// 	}
		// 	glog.V(60).Infof("     EV SevStatus: %s\n", sevStatus.String())
		// }
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA1))
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     secureBoot State enabled: [%t]", sb.Enabled)

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

	glog.V(20).Infof("     TLS Key AuthPolicy [%s]", hex.EncodeToString(decodedTPMNTPublic.AuthPolicy))

	// Verify the TPM key Attributes
	// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L147
	//   tpm2.FlagSignerDefault ^ tpm2.FlagRestricted
	// where
	// https://pkg.go.dev/github.com/google/go-tpm/legacy/tpm2#KeyProp
	// FlagSignerDefault = FlagSign | FlagRestricted | FlagFixedTPM | FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth

	tlsKeyProps := decodedTPMNTPublic.Attributes
	glog.V(20).Infof("     TLS Key TPM Properties mask: %d", tlsKeyProps)

	expectedAttributeMask := tpm2.FlagSign | tpm2.FlagRestricted | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth ^ tpm2.FlagRestricted
	glog.V(20).Infof("     TLS Key Expected Properties mask %d", expectedAttributeMask)

	if expectedAttributeMask != tlsKeyProps {
		glog.Errorf("error TLS Key attribute mismatch, expected [%d], got [%d]", expectedAttributeMask, tlsKeyProps)
		os.Exit(1)
	}

	// extract the PEM key
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

	certifyPubbytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
	if err != nil {
		glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
		os.Exit(1)
	}
	certifyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: certifyPubbytes,
		},
	)

	// compare the verified PEM key with the key associated with the tls cert
	if tlsECCPub.Equal(remoteTLScert.PublicKey) {
		glog.V(5).Info("     Certified TPMNTPublic key matches public key in x509 certificate")
	} else {
		glog.Errorf("ERROR:  Certified TPMNTPublic key does not matches public key in x509 certificate")
		os.Exit(1)
	}

	glog.V(5).Infof("     TLS key verified")
	glog.V(5).Infof("=============== end NewKey ===============")

	// now that we trust the TLS key, connect  over HTTPS
	glog.V(5).Infof("=============== start http client ===============")

	tlsRootPEM, err := os.ReadFile(*dynamicCaCert)
	if err != nil {
		glog.Errorf("Error Reading root %v", err)
		os.Exit(1)
	}

	tlsRoots := x509.NewCertPool()
	ok = tlsRoots.AppendCertsFromPEM([]byte(tlsRootPEM))
	if !ok {
		glog.Errorf("failed to parse root certificate")
		os.Exit(1)
	}

	dynamicTLSConfig := &tls.Config{
		RootCAs:    tlsRoots,
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

			// *** This is the critical part: compare the peer public key with the one that was certified
			if tlsECCPub.Equal(peerPubKey) {
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
