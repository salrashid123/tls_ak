## TPM based TLS using Attested Keys

`TLS` where the private key on the server is bound to its `Trusted Platform Module (TPM)`.  That same TLS key is also attested through full [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

TPM based TLS is a known technology where the private key used for TLS is embedded inside a
peer's `Trusted Platform Module (TPM)`. However, TLS usually requires an x509 certificate which is
itself signed by a certificate authority the peer trusts. The remote client has to trust the certificate
issuer and that the private key resides on a TPM.

This repo describes steps whereby a remote party uses standard [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) to ensure a keypair is resident on a TPM and then establishes TLS to the remote host by comparing
the peer's Public Key values during session setup. The distinguishing characteristic of this flow is
the TLS Certificate by itself or the CA that the peer uses is not necessarily trusted but serves as a
conduit to create the TLS session and derive the fact that the session uses the trusted public key
on the TPM. The client trusts the TLS session not based on the x509 certificate alone of the peer or
CA but by comparing the Public Key used in the session matches what is on the TPM confirmed
through remote attestation and certification of the key.

Essentially, the trusted authority that issues the x509 certificate for TLS is not strictly trusted but yet the
client can ensure the TLS session terminates on a device that is confirmed to host the session's private key

This ensures the client is connecting to the remote host where the TPM resides


1. Server starts the gRPC service with default TLS configuration using ordinary rsa key files
2. Server creates an `Attestation Key (AK)`
3. Server creates a new elliptic key on the TPM for TLS and uses the attestation key to certify it.
4. Server issues an `x509` using a local CA for the key in step 3
5. Server launches a new `HTTPS` server where the server certificate and private key from step 3

6. Client contacts server over default TLS and requests its `Endorsement Public Key (EKPub)`
7. Client contacts server requesting `Attestation Key (AK)`
8. Client and Server perform TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
9. CLient and Server perform TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify) to ensure the server state is correct
10. Client connects to server and requests the attested TLS key from step 3.
11. Client verifies the TLS key is attested by the AK

10. Client connects to the HTTPs server and compares the TLS sessions EC Public Key is the same as step step 11 (meaning its talking to that TPM's key)

Basically the `gRPC` server part (1->11) does some background steps to establish trust on the EC key.

After that, a new `HTTPS` server is launched which uses the EC Key on the TPM and a certificate signed by a local CA.

![images/flow.png](images/flow.png)

so whats so good about this?  well, your client is _assured_ that they are terminating the TLS connection on that VM that includes that specific TPM.

Note the part where CA certificate (local or otherwise) which issues the x509 (step 4) isn't the critical part in this flow:  the fact that the attested _EC Public Key matches whats in the certificate and TLS session is important_.  If you wanted, instead of the attestor's CA that issues the x509, the server could have sent a CSR to the client (or privacy CA) for issuance.

for reference, see

* [TPM remote attestation: How can I trust you?](https://community.infineon.com/t5/Blogs/TPM-remote-attestation-How-can-I-trust-you/ba-p/452729)
* [OpenEnclave AttestedTLS](https://github.com/openenclave/openenclave/blob/master/samples/attested_tls/AttestedTLSREADME.md)
* [Using Attestation in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)](https://datatracker.ietf.org/doc/draft-fossati-tls-attestation/)
* [BlindLlama TLS](https://blindllama.mithrilsecurity.io/en/latest/docs/concepts/TPMs/) 
* [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf) (`5.2 OEM Creation of IAK and IDevID in a Single Pass`)

---

>> NOTE: this repo and code is *not* supported by google

---

### Setup

There are two ways to test this:

1. locally with your laptop 
2. on a cloud vm (eg GCP confidential VM with a TPM)

In both cases, you'll need to have access to the eventlog on the attestor, eg this should return values only on the attestor

```bash
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurement
```

In both cases, the EK Cert needs to get verified to the roots so there is a bit of legwork in getting the cert chain setup


#### Local 

You can also verify this demo locally if your user has access to both the TPM and the event log. 

For me, the TPM was issued by `C=CH, O=STMicroelectronics NV, CN=STSAFE TPM RSA Intermediate CA 10`

for which the verification  certs were found [here](https://www.st.com/resource/en/technical_note/tn1330-st-trusted-platform-module-tpm-endorsement-key-ek-certificates-stmicroelectronics.pdf)

```bash
## ekpublic
$ tpm2_createek -c ek.ctx -G rsa -u ek.pub 
$ tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -Q

## ekcert
$ tpm2_getekcertificate -X -o ECcert.bin
$ openssl x509 -in ECcert.bin -inform DER -noout -text

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                7e:36:61:65:3e:7b:5a:81:74:3d:03:f1:1a:92:56:ec:ff:be:04:81
            Signature Algorithm: sha384WithRSAEncryption
            Issuer: C=CH, O=STMicroelectronics NV, CN=STSAFE TPM RSA Intermediate CA 10  <<<<<<<<<<<<<<<<<<
            Validity
                Not Before: Apr 16 10:33:45 2023 GMT
                Not After : Dec 31 23:59:59 9999 GMT
            Subject: 
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    Public-Key: (2048 bit)
                    Modulus:
                        00:d2:c8:63:53:
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Authority Key Identifier: 
                    65:70:62:A7:10:56:91:6F:8C:7F:79:8A:92:DD:E6:D8:1D:0A:98:DA
                X509v3 Subject Alternative Name: critical
                    DirName:/tcg-at-tpmManufacturer=id:53544D20/tcg-at-tpmModel=ST33KTPM2X/tcg-at-tpmVersion=id:00090100
                X509v3 Subject Directory Attributes: 
                    TPM Specification:
        0:d=0  hl=2 l=  12 cons: SEQUENCE          
        2:d=1  hl=2 l=   3 prim:  UTF8STRING        :2.0
        7:d=1  hl=2 l=   1 prim:  INTEGER           :00
        10:d=1  hl=2 l=   2 prim:  INTEGER           :9F


                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Extended Key Usage: 
                    Endorsement Key Certificate
                X509v3 Key Usage: critical
                    Key Encipherment
                Authority Information Access: 
                    CA Issuers - URI:http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt <<<<<<<<<<<<<<<<<<<
```

for my local tpm, the value for the EKCert had an issuer below so we  need to get that too

```bash
### STSAFE TPM RSA Intermediate CA 10 http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt
$ wget http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt

$ openssl x509 -in stsafetpmrsaint10.crt -inform DER -noout -text

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 1073741840 (0x40000010)
            Signature Algorithm: sha384WithRSAEncryption
            Issuer: C=CH, O=STMicroelectronics NV, CN=STSAFE RSA Root CA 02
            Validity
                Not Before: Jan 20 00:00:00 2022 GMT
                Not After : Jan  1 00:00:00 2042 GMT
            Subject: C=CH, O=STMicroelectronics NV, CN=STSAFE TPM RSA Intermediate CA 10
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    Public-Key: (4096 bit)
                    Modulus:
                        00:cb:b5:33:...
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Subject Key Identifier: 
                    65:70:62:A7:10:56:91:6F:8C:7F:79:8A:92:DD:E6:D8:1D:0A:98:DA
                X509v3 Authority Key Identifier: 
                    7C:C2:8D:BE:6E:59:D8:4A:54:03:46:9B:13:08:00:D2:F8:F0:6D:27
                X509v3 Certificate Policies: critical
                    Policy: X509v3 Any Policy
                    CPS: http://sw-center.st.com/STSAFE/
                X509v3 Key Usage: critical
                    Certificate Sign, CRL Sign
                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:0
                Authority Information Access: 
                    CA Issuers - URI:http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt <<<<<<<<<<<<<<<<<<<<<<<
                X509v3 CRL Distribution Points: 
                    Full Name:
                    URI:http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crl

        Signature Algorithm: sha384WithRSAEncryption 

```

Which you can also get from the doc above, page 5 

To get the root, again on pg5 of the doc `STSAFE RSA Root CA 02 http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt`

```bash
$ wget  http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt
$ openssl x509 -in STSAFERsaRootCA02.crt  -inform DER -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 93583579283458 (0x551d20000002)
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C=CH, O=STMicroelectronics NV, CN=STSAFE RSA Root CA 02
        Validity
            Not Before: Jan 20 00:00:00 2022 GMT
            Not After : Dec 31 00:00:00 9999 GMT
        Subject: C=CH, O=STMicroelectronics NV, CN=STSAFE RSA Root CA 02
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:c8:3b:47:6d:..
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                7C:C2:8D:BE:6E:59:D8:4A:54:03:46:9B:13:08:00:D2:F8:F0:6D:27
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha384WithRSAEncryption
```

The PCR values `PCR0` were:

```bash
$ tpm2_pcrread
  sha256:
    0 : 0x7BB4353897632FD086982175A027DAFCC33F61ADBAB4EBFC6D13927B97A8C084
```

Now, both of these are DER files so to convert to PEM:

```bash
openssl x509 -in stsafetpmrsaint10.crt -inform DER -noout -text certs/stsafetpmrsaint10.pem
openssl x509 -in STSAFERsaRootCA02.crt -inform DER -noout -text -out certs/stmtpmekroot.pem
```

So to run, i used

```bash
go run server/grpc_attestor.go --grpcport :50051 --applicationPort :8081  --v=10 -alsologtostderr

export ATTESTOR_ADDRESS=127.0.0.1
go run client/grpc_verifier.go --host=127.0.0.1:50051 \
   --appaddress=$ATTESTOR_ADDRESS:8081      --ekintermediateCA=certs/stsafetpmrsaint10.pem  --ekrootCA=certs/stmtpmekroot.pem  --expectedPCRMapSHA256=0:7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084     --v=10 -alsologtostderr
```

The output is like this on both ends

#### Verifier

```bash
$ go run client/grpc_verifier.go --host=127.0.0.1:50051 \
   --appaddress=$ATTESTOR_ADDRESS:8081   \
      --ekintermediateCA=certs/stsafetpmrsaint10.pem  \
       --ekrootCA=certs/stmtpmekroot.pem \
        --expectedPCRMapSHA256=0:7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084 \
            --v=10 -alsologtostderr

I1004 15:17:10.506757 3468104 grpc_verifier.go:95] =============== start GetEK ===============
I1004 15:17:10.516616 3468104 grpc_verifier.go:235]         EKCertificate ========
-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIUfjZhZT57WoF0PQPxGpJW7P++BIEwDQYJKoZIhvcNAQEM
BQAwWTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBO
VjEqMCgGA1UEAxMhU1RTQUZFIFRQTSBSU0EgSW50ZXJtZWRpYXRlIENBIDEwMCAX
DTIzMDQxNjEwMzM0NVoYDzk5OTkxMjMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVxNtZA7hGxA1MeC891SLmn
OMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9FoPBA//coeFavi7cjV9GUh
3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8XIJwjCfnSWGCAo16FadU
xteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiwMAyKXdIncJnNaKi8qLDl
D4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI11LvCiNCWGAJZ7pxTME7
+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOegVwIDAQABo4IBJDCCASAw
HwYDVR0jBBgwFoAUZXBipxBWkW+Mf3mKkt3m2B0KmNowVwYDVR0RAQH/BE0wS6RJ
MEcxFjAUBgVngQUCAQwLaWQ6NTM1NDREMjAxFTATBgVngQUCAgwKU1QzM0tUUE0y
WDEWMBQGBWeBBQIDDAtpZDowMDA5MDEwMDAiBgNVHQkEGzAZMBcGBWeBBQIQMQ4w
DAwDMi4wAgEAAgIAnzAMBgNVHRMBAf8EAjAAMBAGA1UdJQQJMAcGBWeBBQgBMA4G
A1UdDwEB/wQEAwIFIDBQBggrBgEFBQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6
Ly9zdy1jZW50ZXIuc3QuY29tL1NUU0FGRS9zdHNhZmV0cG1yc2FpbnQxMC5jcnQw
DQYJKoZIhvcNAQEMBQADggIBAKNipPkkgRUMAyTJh8xWRAmOP2put6d/DEuVsYRn
hvsVwJPUYc2Ki1hm8fy8OCnRAcChwQDj0tgcyAjol1qusSG5Z+pkIwdet4WLcYiE
0uf/EWMz4xvsmIDDIpn38flbAM+5XjsVczGC8/WM2DFxSllmmD5BpZDm0tBDnwCU
3bpBNoeUZ/gGoYNdDxWPnwqc5Zy1+AheaigQzGUPFKRU2xMuBkOTmdJgY357dvLZ
vVrJUWGSJq8Ee/bRgj/UFFPABLFQgV8S8x7HnMxmwUUwgHC3F94wEs5/mo/VQXbU
uJ2TlKhT3Dy/3ssKjNgVOnIOb7G54yjg2CzR8ncI9oz0QGJm4P243Zv+iBSsKTXb
2di1CxWuuE7s23ajExBnTKTfnERfeHbtiT8MUqre02kDHX8ql/xrM0fOq02+JODZ
U0DnsZI3wXDEvjRy8X+GyiDGU+wnpgycSNzoSAWvvIRxRdqcaZ4QJh9diABX41CE
teI4QdS32b7LejPcbJH566NhlPReZDFgssIEGjdYYLaGFZdya3YEqgZMfyRfVL16
93DBivvYwgtyqQj+aKAhAGLJTQEXqdQh662hMPZ5bBQS8FZ8MncS6CodLYvsXJUw
qYloxK9lcNDk0rkIibqzSUL1+lPbpQwE2xV+LQZbNIyj2hQ6XTYmwrsT+C8Fp/vU
Cfz7
-----END CERTIFICATE-----

I1004 15:17:10.516782 3468104 grpc_verifier.go:251]      EKCert  Issuer CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
I1004 15:17:10.516869 3468104 grpc_verifier.go:252]      EKCert  IssuingCertificateURL [http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt]
I1004 15:17:10.516898 3468104 grpc_verifier.go:257]     Verifying EKCert
I1004 15:17:10.517241 3468104 grpc_verifier.go:285]      EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage 2.23.133.8.1
I1004 15:17:10.519039 3468104 grpc_verifier.go:312]     EKCert Verified
I1004 15:17:10.519095 3468104 grpc_verifier.go:314]      EKPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVx
NtZA7hGxA1MeC891SLmnOMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9Fo
PBA//coeFavi7cjV9GUh3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8
XIJwjCfnSWGCAo16FadUxteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiw
MAyKXdIncJnNaKi8qLDlD4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI
11LvCiNCWGAJZ7pxTME7+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOeg
VwIDAQAB
-----END PUBLIC KEY-----

I1004 15:17:10.519175 3468104 grpc_verifier.go:330] =============== end GetEKCert ===============
I1004 15:17:10.519211 3468104 grpc_verifier.go:333] =============== start GetAK ===============
I1004 15:17:10.941154 3468104 grpc_verifier.go:366]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIVIhExwXD6mAWq2DDNm
SOCQgbJjgBAhXocB3X92QAb2Mq9/uq7qCuUelpKkJG0yXg47XDWb5HwiME67lZZX
YwOfPufTcyEZGZtoZ7HPYaGE1P8tToMsvBcL7B72f0LsRTovT2z/0eUhu3qZYUk4
pJTjGA2Avp6q6oRL8LvXZu/663Z9tpA1N636PISYaqfIDjF96/C3Zs21FAByZuGP
AUbMkIBTKbohTET+3ub0jAJC4lluoj5IHvh2DDFntKkp3IrWkFDYsr7Er718aaXO
+WqNQlD6+rSe96Xriuupuepl69MILBBi6/EUblsainMiqnlD3U6bOOUSMtKFyaUm
fQIDAQAB
-----END PUBLIC KEY-----

I1004 15:17:10.941248 3468104 grpc_verifier.go:367] =============== end GetAK ===============
I1004 15:17:10.941291 3468104 grpc_verifier.go:370] =============== start Attest ===============
I1004 15:17:10.941821 3468104 grpc_verifier.go:383]       Outbound Secret: 0aoYEFewrDlouNNFVg352om8xeKlmG2YXfQnn0fZiww=
I1004 15:17:12.944150 3468104 grpc_verifier.go:399]       Inbound Secret: 0aoYEFewrDlouNNFVg352om8xeKlmG2YXfQnn0fZiww=
I1004 15:17:12.944252 3468104 grpc_verifier.go:402]       inbound/outbound Secrets Match; accepting AK
I1004 15:17:12.944296 3468104 grpc_verifier.go:407] =============== end Attest ===============
I1004 15:17:12.944328 3468104 grpc_verifier.go:410] =============== start Quote/Verify ===============
I1004 15:17:19.159058 3468104 grpc_verifier.go:455]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIVIhExwXD6mAWq2DDNm
SOCQgbJjgBAhXocB3X92QAb2Mq9/uq7qCuUelpKkJG0yXg47XDWb5HwiME67lZZX
YwOfPufTcyEZGZtoZ7HPYaGE1P8tToMsvBcL7B72f0LsRTovT2z/0eUhu3qZYUk4
pJTjGA2Avp6q6oRL8LvXZu/663Z9tpA1N636PISYaqfIDjF96/C3Zs21FAByZuGP
AUbMkIBTKbohTET+3ub0jAJC4lluoj5IHvh2DDFntKkp3IrWkFDYsr7Er718aaXO
+WqNQlD6+rSe96Xriuupuepl69MILBBi6/EUblsainMiqnlD3U6bOOUSMtKFyaUm
fQIDAQAB
-----END PUBLIC KEY-----

I1004 15:17:19.159315 3468104 grpc_verifier.go:482]      quotes verified
I1004 15:17:19.159671 3468104 grpc_verifier.go:518] =============== end Quote/Verify ===============
I1004 15:17:19.159734 3468104 grpc_verifier.go:521] =============== start NewKey ===============
I1004 15:17:19.571076 3468104 grpc_verifier.go:533]         TLSCertificate ========
-----BEGIN CERTIFICATE-----
MIIDdDCCAlygAwIBAgIQf3NkrwTMf3NuYmgaPXKNFTANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMSIwIAYDVQQDDBlTaW5nbGUgUm9vdCBUTFMgSXNzdWVyIENBMB4XDTI1MTAw
NDA2MTcwMloXDTI1MTAwNTA2MTcwMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdB
Y21lIENvMRMwEQYDVQQLEwpFbnRlcnByaXNlMTgwNgYDVQQDDC90cG1fc2VydmVy
IDY2YjU1YTNkLWUxY2ItNDZkNi05MjhmLWM4MjRhZjI4ZjdjZjEtMCsGA1UEBRMk
NjZiNTVhM2QtZTFjYi00NmQ2LTkyOGYtYzgyNGFmMjhmN2NmMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wykTHu5ZEzf49yC8Cg
6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sKOBkjCBjzAOBgNVHQ8BAf8E
BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNVHSME
GDAWgBRbzaql97VlJoV0gg2BK5pBDzb68DAaBgNVHREEEzARgg9lY2hvLmRvbWFp
bi5jb20wHQYDVR0gBBYwFDAIBgZngQULAQEwCAYGZ4EFCwECMA0GCSqGSIb3DQEB
CwUAA4IBAQAlM++WRmMPtQuBuLVxYPI07mp/1TFjm5xPKZMGvIif6UMxGHsqhSyt
3XRS+crVV1Apx2ZdOJvZ3keNvfp9yyyFTiL+iX2/S9//9DkB5XuHbshFK0vv4uxC
oF+7qoe4iZSNi8hUmr+dZElLR/VVC3Qlbxqchq7aZs0cyTBo80JaL7tWNVSZwgR8
NYeimADu6dfIWfr2Jrf7pO9MSvvT6yLwMPeVCmEAXIzruuaSpaIUjmN7aHAlOxsa
HeLD6WHFmpdnloEawW0Q8D15yDi8iwyGdIDDpY4Cu9vcqQwAm8k+6229mhlsvBkG
VyXrQ9YSVBCmRBuVxNG7bpOwMLmYFRnQ
-----END CERTIFICATE-----

I1004 15:17:19.571295 3468104 grpc_verifier.go:541]         TLCertificate Issuer CN: Single Root TLS Issuer CA
I1004 15:17:19.571385 3468104 grpc_verifier.go:542]         TLCertificate Subjec : SERIALNUMBER=66b55a3d-e1cb-46d6-928f-c824af28f7cf,CN=tpm_server 66b55a3d-e1cb-46d6-928f-c824af28f7cf,OU=Enterprise,O=Acme Co,L=Mountain View,ST=California,C=US
I1004 15:17:19.571445 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.15, Critical: true, Value (DER): 03020780
I1004 15:17:19.571509 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.37, Critical: false, Value (DER): 300a06082b06010505070301
I1004 15:17:19.571542 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.19, Critical: true, Value (DER): 3000
I1004 15:17:19.571562 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.35, Critical: false, Value (DER): 301680145bcdaaa5f7b565268574820d812b9a410f36faf0
I1004 15:17:19.571584 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.17, Critical: false, Value (DER): 3011820f6563686f2e646f6d61696e2e636f6d
I1004 15:17:19.571600 3468104 grpc_verifier.go:545]         Extension: OID: 2.5.29.32, Critical: false, Value (DER): 3014300806066781050b0101300806066781050b0102
I1004 15:17:19.571642 3468104 grpc_verifier.go:558]        public key from cert 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wy
kTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sA==
-----END PUBLIC KEY-----

I1004 15:17:19.571957 3468104 grpc_verifier.go:629]      Certified TPMNTPublic key matches public key in x509 certificate
I1004 15:17:19.572022 3468104 grpc_verifier.go:635]      TLS key verified
I1004 15:17:19.572090 3468104 grpc_verifier.go:636] =============== end NewKey ===============
I1004 15:17:19.572155 3468104 grpc_verifier.go:639] =============== start http client ===============
I1004 15:17:19.697417 3468104 grpc_verifier.go:704]       Issuer CN=Single Root TLS Issuer CA,OU=Enterprise,O=Google,C=US
I1004 15:17:19.697540 3468104 grpc_verifier.go:717]        peer public key 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wy
kTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sA==
-----END PUBLIC KEY-----

I1004 15:17:19.697575 3468104 grpc_verifier.go:726]      peer tls public key matched attested key
I1004 15:17:19.697605 3468104 grpc_verifier.go:733]      Connected to IP: 127.0.0.1
I1004 15:17:19.698565 3468104 grpc_verifier.go:752] 200 OK
I1004 15:17:19.698690 3468104 grpc_verifier.go:753] ok
```

#### Attestor

```bash
$ sudo go run server/grpc_attestor.go --grpcport :50051 --applicationPort :8081  --v=30 -alsologtostderr

I1004 15:17:00.757803 3467978 grpc_attestor.go:317] Getting EKCert
I1004 15:17:00.775051 3467978 grpc_attestor.go:337] ECCert with available Issuer: CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
I1004 15:17:02.298713 3467978 grpc_attestor.go:433] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wy
kTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sA==
-----END PUBLIC KEY-----
I1004 15:17:02.298775 3467978 grpc_attestor.go:446]         Issuing Cert ========
I1004 15:17:02.421868 3467978 grpc_attestor.go:524]       CSR 
-----BEGIN CERTIFICATE REQUEST-----
MIIBtDCCAVoCAQAwgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBY21lIENvMRMwEQYD
VQQLEwpFbnRlcnByaXNlMTgwNgYDVQQDDC90cG1fc2VydmVyIDY2YjU1YTNkLWUx
Y2ItNDZkNi05MjhmLWM4MjRhZjI4ZjdjZjEtMCsGA1UEBRMkNjZiNTVhM2QtZTFj
Yi00NmQ2LTkyOGYtYzgyNGFmMjhmN2NmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEJzdCPv9URzkVwuehzHfVbvLSF8wykTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCg
CxY/hZzPwOgvS3SIVyGHQWU4sKAtMCsGCSqGSIb3DQEJDjEeMBwwGgYDVR0RBBMw
EYIPZWNoby5kb21haW4uY29tMAoGCCqGSM49BAMCA0gAMEUCIE/ZCjf7HEBjF2QE
hxL4l2sgFq5sWlFCjHrzJmITQbSbAiEA1N8gmXtDQdpomKs3VtBh/rYkXNBIz6NG
01uvVveXZN4=
-----END CERTIFICATE REQUEST-----

I1004 15:17:02.424826 3467978 grpc_attestor.go:583]         cert Issuer CN=Single Root TLS Issuer CA,OU=Enterprise,O=Google,C=US
I1004 15:17:02.424876 3467978 grpc_attestor.go:586]         Issued Certificate ========
-----BEGIN CERTIFICATE-----
MIIDdDCCAlygAwIBAgIQf3NkrwTMf3NuYmgaPXKNFTANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMSIwIAYDVQQDDBlTaW5nbGUgUm9vdCBUTFMgSXNzdWVyIENBMB4XDTI1MTAw
NDA2MTcwMloXDTI1MTAwNTA2MTcwMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdB
Y21lIENvMRMwEQYDVQQLEwpFbnRlcnByaXNlMTgwNgYDVQQDDC90cG1fc2VydmVy
IDY2YjU1YTNkLWUxY2ItNDZkNi05MjhmLWM4MjRhZjI4ZjdjZjEtMCsGA1UEBRMk
NjZiNTVhM2QtZTFjYi00NmQ2LTkyOGYtYzgyNGFmMjhmN2NmMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wykTHu5ZEzf49yC8Cg
6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sKOBkjCBjzAOBgNVHQ8BAf8E
BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNVHSME
GDAWgBRbzaql97VlJoV0gg2BK5pBDzb68DAaBgNVHREEEzARgg9lY2hvLmRvbWFp
bi5jb20wHQYDVR0gBBYwFDAIBgZngQULAQEwCAYGZ4EFCwECMA0GCSqGSIb3DQEB
CwUAA4IBAQAlM++WRmMPtQuBuLVxYPI07mp/1TFjm5xPKZMGvIif6UMxGHsqhSyt
3XRS+crVV1Apx2ZdOJvZ3keNvfp9yyyFTiL+iX2/S9//9DkB5XuHbshFK0vv4uxC
oF+7qoe4iZSNi8hUmr+dZElLR/VVC3Qlbxqchq7aZs0cyTBo80JaL7tWNVSZwgR8
NYeimADu6dfIWfr2Jrf7pO9MSvvT6yLwMPeVCmEAXIzruuaSpaIUjmN7aHAlOxsa
HeLD6WHFmpdnloEawW0Q8D15yDi8iwyGdIDDpY4Cu9vcqQwAm8k+6229mhlsvBkG
VyXrQ9YSVBCmRBuVxNG7bpOwMLmYFRnQ
-----END CERTIFICATE-----

I1004 15:17:02.424957 3467978 grpc_attestor.go:600]         Issued certificate tied to PubicKey ========
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wy
kTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sA==
-----END PUBLIC KEY-----

I1004 15:17:02.425167 3467978 grpc_attestor.go:624] Starting HTTP Server on port :8081
I1004 15:17:02.425843 3467978 grpc_attestor.go:664] Starting gRPC server on port :50051

usign signer
I1004 15:17:10.515854 3467978 grpc_attestor.go:171] ======= GetEK ========
I1004 15:17:10.519842 3467978 grpc_attestor.go:183] ======= GetAK ========
I1004 15:17:10.942363 3467978 grpc_attestor.go:206] ======= Attest ========
I1004 15:17:12.945011 3467978 grpc_attestor.go:240] ======= Quote ========
I1004 15:17:19.160295 3467978 grpc_attestor.go:277] ======= GetTLSKey ========
usign signer
I1004 15:17:19.698001 3467978 grpc_attestor.go:301] Inbound HTTP request from: 127.0.0.1
```

What you'll see in the output is the full remote attestation, then a certificate issued with a specific public key where the private key is on the TPM (and is attested by AK)

The client connects to the server and prints the public key....the fact the same public keys are shown confirms the attested key on the TPM is at the other end of the TLS session.

---

Once the https server is running, you can continue to interact with it on port `:8081`

```bash
$ curl -vvv --cacert certs/issuer_ca.crt    --resolve  echo.domain.com:8081:$ATTESTOR_ADDRESS https://echo.domain.com:8081/

$ openssl s_client --connect $ATTESTOR_ADDRESS:8081
```

Note the certificate specifications and public key matches the attested EC public key that was tied to the TPM

```bash
$ openssl s_client -connect $ATTESTOR_ADDRESS:8081 | openssl x509 -pubkey -noout

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJzdCPv9URzkVwuehzHfVbvLSF8wy
kTHu5ZEzf49yC8Cg6UOqe+JR5B/mgFCgCxY/hZzPwOgvS3SIVyGHQWU4sA==
-----END PUBLIC KEY-----
```

---

### GCP

To test on GCP, you have to do a similar flow except acqure the CA certs for your environment

```bash
gcloud compute instances create attestor   \
   --zone=us-central1-a --machine-type=n2d-standard-2 --no-service-account --no-scopes \
      --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --maintenance-policy=MIGRATE --min-cpu-platform="AMD Milan"  --confidential-compute-type=SEV \
      --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

## allow grpc
gcloud compute firewall-rules create allow-tpm-verifier  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:50051

## allow http
gcloud compute firewall-rules create allow-tpm-verifier-https  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:8081

$ gcloud compute instances list
NAME      ZONE           MACHINE_TYPE    PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP   STATUS
attestor  us-central1-a  n2d-standard-2               10.128.15.225  34.30.250.78  RUNNING

export ATTESTOR_ADDRESS=34.30.250.78

# optionally if you installed TPM2_TOOLS, you can print the PCR value
# on the vm type above, PCR0 is
# tpm2_pcrread sha256:0
#  sha256:
#    0 : 0xA0B5FF3383A1116BD7DC6DF177C0C2D433B9EE1813EA958FA5D166A202CB2A85
```

Now, since we're on GCP, get the EK Signing and intermediate certificates.  For other manufacturers, you can usually lookup the manufacturers CA out of band, eg for `CN=STM TPM EK Intermediate CA 06,O=STMicroelectronics NV,C=CH` they're listed [here](https://www.st.com/resource/en/technical_note/tn1330-st-trusted-platform-module-tpm-endorsement-key-ek-certificates-stmicroelectronics.pdf)

```bash
## get the EK
gcloud compute instances get-shielded-identity attestor --format=json --zone=us-central1-a | jq -r '.encryptionKey.ekCert' > certs/ekcert.pem

## get the intermediate from the ek
curl -s $(openssl x509 -in certs/ekcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_intermediate.pem

## get the root from the intermediate
curl -s $(openssl x509 -in certs/ek_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_root.pem
```

#### Attestor

SSH to the attestor, [install golang](https://go.dev/doc/install) and run

```bash
$ git clone https://github.com/salrashid123/tls_ak.git

$ go run server/grpc_attestor.go --grpcport :50051 --applicationPort :8081 --v=10 -alsologtostderr
```

install [tpm2-tools](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) (`apt-get install tpm2-tools`) and print out the PCR=0 value. 

For me on GCE VM, it was

```bash
$ tpm2_pcrread sha256:0
  sha256:
    0 : 0xA0B5FF3383A1116BD7DC6DF177C0C2D433B9EE1813EA958FA5D166A202CB2A85
```

This PCR value is what the verifier checks via quote/verify later


#### Verifier

On the laptop, run the verifier (remember to specify the expected lowercase PCR value)

```bash
$ go run client/grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
   --appaddress=$ATTESTOR_ADDRESS:8081 \
   --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
    --v=10 -alsologtostderr
```

---

#### TLS-PSK

Another variation of this is to use [TLS-PSK](https://www.rfc-editor.org/rfc/rfc4279) between single client->server.

This mode is designed for a single client to connect to a single server where the TLS session is created using a pre-shared key which is itself securely transferred from the client to the server after remote attestation.  That PSK is used to launch a new TLS session which does not involve certificates.

Unfortunately, go does not yet support PSK: [issue 6379](https://github.com/golang/go/issues/6379#issuecomment-2079691128)

Just note that this variant does not *ensure* the TLS remote peer terminates on a TPM but just that the EK associated with the TPM did at some point decrypt the PSK.  In other words, the PSK can get decrypted by the EK but then turn around and share that PSK with another system that does setup TLS.

![images/pks.png](images/psk.png)

Anyway, once its ready, you can securely transfer a PSK directly using 

* on client [server.CreateImportBlob()](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.4.4/server#CreateImportBlob)
* on server [client.Key.Import()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.Import)

(yes, i know, the package names in the go library is inverted)

for further examples, see:

- [Go-TPM-Wrapping - Go library for encrypting data using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)
- [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation?tab=readme-ov-file#aes)
- [Multiparty Consent Based Networks (MCBN)](https://github.com/salrashid123/mcbn)
