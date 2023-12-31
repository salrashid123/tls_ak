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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"

	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"

	"github.com/salrashid123/tls_ak/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	address              = flag.String("host", "localhost:50051", "host:port of gRPC server")
	appaddress           = flag.String("appaddress", "localhost:8081", "host:port of gRPC server")
	tlsCert              = flag.String("tlsCert", "../certs/ca.crt", "tls Certificate")
	dynamicCaCert        = flag.String("dynamicCaCert", "../certs/issuer_ca.crt", "tls Certificate for dynamic issuer")
	grpcServerName       = flag.String("grpcservername", "attestor.esodemoapp2.com", "SNI for grpc server")
	httpServerName       = flag.String("httpservername", "echo.esodemoapp2.com", "SNI for http server")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")

	u   = flag.String("uid", uuid.New().String(), "uid of client")
	kid = flag.String("kid", uuid.New().String(), "keyid to save")

	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
	var err error

	var tlsCfg tls.Config
	rootCAs := x509.NewCertPool()
	ca_pem, err := ioutil.ReadFile(*tlsCert)
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

	//conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	glog.V(5).Infof("=============== start GetEK ===============")

	ekReq := &verifier.GetEKRequest{}

	c := verifier.NewVerifierClient(conn)
	ekResponse, err := c.GetEK(ctx, ekReq)
	if err != nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	// first try to verify the ekcert (if available; its not on GCP)

	var ekPubPEM []byte
	if len(ekResponse.EkCert) > 0 {
		ekcert, err := x509.ParseCertificate(ekResponse.EkCert)
		if err != nil {
			glog.Errorf("ERROR:   ParseCertificate: %v", err)
			os.Exit(1)
		}
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

		gceInfo, err := server.GetGCEInstanceInfo(ekcert)
		if err == nil && gceInfo != nil {
			glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
			glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
			glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
		}

		glog.V(10).Infof("    EkCert Public Key \n%s\n", ekPubPEM)
		// todo verify the ekcert chain
		// glog.V(10).Info("    Verifying EKCert")

		// rootPEM, err := ioutil.ReadFile(*ekRootCA)
		// if err != nil {
		// 	glog.Errorf("Error Reading root %v", err)
		// 	os.Exit(1)
		// }

		// roots := x509.NewCertPool()
		// ok := roots.AppendCertsFromPEM([]byte(rootPEM))
		// if !ok {
		// 	glog.Errorf("failed to parse root certificate")
		// 	os.Exit(1)
		// }

		// interPEM, err := ioutil.ReadFile(*ekIntermediate)
		// if err != nil {
		// 	glog.Errorf("Error Reading intermediate %v", err)
		// 	os.Exit(1)
		// }

		// inters := x509.NewCertPool()
		// ok = inters.AppendCertsFromPEM(interPEM)
		// if !ok {
		// 	glog.Errorf("failed to parse intermediate certificate")
		// 	os.Exit(1)
		// }

		// ekcert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
		// _, err = ekcert.Verify(x509.VerifyOptions{
		// 	Roots:         roots,
		// 	Intermediates: inters,
		// 	KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// })
		// if err != nil {
		// 	glog.Errorf("Error Reading intermediate %v", err)
		// 	os.Exit(1)
		// }
		// glog.V(10).Info("    EKCert Verified")
	} else {
		ekPubPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: ekResponse.EkPub,
			},
		)
	}

	glog.V(5).Infof("     EKPub: \n%s\n", ekPubPEM)

	bblock, _ := pem.Decode(ekPubPEM)
	if bblock == nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	ekPub, err := x509.ParsePKIXPublicKey(bblock.Bytes)
	if err != nil {
		glog.Errorf("Error parsing ekpub: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("=============== end GetEKCert ===============")

	glog.V(5).Infof("=============== start GetAK ===============")
	akResponse, err := c.GetAK(ctx, &verifier.GetAKRequest{
		Uid: *u,
	})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	serverAttestationParameter := &attest.AttestationParameters{}
	reader := bytes.NewReader(akResponse.Ak)
	err = json.NewDecoder(reader).Decode(serverAttestationParameter)
	if err != nil {
		glog.Errorf("Error encoding serverAttestationParamer %v", err)
		os.Exit(1)
	}

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekPub,
		AK:         *serverAttestationParameter,
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

	glog.V(5).Infof("=============== start Attest ===============")
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
		Uid:                  *u,
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

	glog.V(5).Infof("=============== start Quote/Verify ===============")

	nonce := []byte(uuid.New().String())
	quoteResponse, err := c.Quote(ctx, &verifier.QuoteRequest{
		Uid:   *u,
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

	glog.V(5).Infof("=============== start NewKey ===============")

	newKeyResponse, err := c.NewKey(ctx, &verifier.NewKeyRequest{
		Uid: *u,
		Kid: *kid,
	})
	if err != nil {
		glog.Errorf("newKey Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     newkey Public \n%s", newKeyResponse.Public)

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
	glog.V(5).Infof("     new key verified")
	glog.V(5).Infof("=============== end NewKey ===============")

	glog.V(5).Infof("=============== start Sign ===============")

	dataToSign := []byte("foo")
	signResponse, err := c.Sign(ctx, &verifier.SignRequest{
		Uid:  *u,
		Kid:  *kid,
		Data: dataToSign,
	})
	if err != nil {
		glog.Errorf("Sign Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     signature: %s", base64.StdEncoding.EncodeToString(signResponse.Signed))

	hh := sha256.New()
	hh.Write(dataToSign)
	hdigest := hh.Sum(nil)

	block, _ := pem.Decode(newKeyResponse.Public)
	if block == nil {
		glog.Errorf("failed to parse PEM block containing the key: %v", err)
		os.Exit(1)
	}

	rpub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		glog.Errorf("failed to parse ParsePKIXPublicKey: %v", err)
		os.Exit(1)
	}

	ok := ecdsa.VerifyASN1(rpub.(*ecdsa.PublicKey), hdigest, signResponse.Signed)
	if !ok {
		glog.Errorf("Verification failed Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     signature verified")
	glog.V(5).Infof("=============== end Sign ===============")

	glog.V(5).Infof("=============== start StartTLS ===============")

	startTLSResponse, err := c.StartTLS(ctx, &verifier.StartTLSRequest{
		Uid: *u,
		Kid: *kid,
	})
	if err != nil {
		glog.Errorf("startTLSResponse Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("     startTLSResponse status %t", startTLSResponse.Status)

	glog.V(5).Infof("=============== start http client ===============")

	rootPEM, err := ioutil.ReadFile(*dynamicCaCert)
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
	}

	tr := &http.Transport{
		TLSClientConfig: dynamicTLSConfig,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s", *appaddress))
	if err != nil {
		glog.Errorf("Error Reading new host %v", err)
		os.Exit(1)
	}

	derBytes := resp.TLS.PeerCertificates[0].Raw

	p, err := x509.ParseCertificate(derBytes)
	if err != nil {
		glog.Errorf("ERROR:  Failed to  parse certificate: %s", err)
		os.Exit(1)
	}
	glog.V(2).Infof("      Issuer %s\n", p.Issuer)

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(resp.TLS.PeerCertificates[0].PublicKey)
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
	glog.V(5).Infof("     peer public key \n%s\n", kpem)

	// compare the peer key with the one we got from NewKey() call

	if base64.StdEncoding.EncodeToString(newKeyResponse.Public) == base64.StdEncoding.EncodeToString(kpem) {
		glog.V(5).Info("     peer tls public key matched attested key")
	} else {
		glog.Errorf("ERROR:  peer public keys mismatch  expected \n[%s]\n\ngot: \n[%s]", newKeyResponse.Public, kpem)
		os.Exit(1)
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
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
