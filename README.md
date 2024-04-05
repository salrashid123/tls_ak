
## TPM based TLS using Attested Keys

`TLS` where the private key on the server is bound to its `Trusted Platform Module (TPM)` after the keys are attested though [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This ensures the client is connecting to the remote host where the TPM resides

Basically,

1. The server starts with default TLS configuration using ordinary rsa key files
2. Client contacts server over default TLS and requests its `Endorsement Public Key (EKPub)`
3. Client contacts server requesting `Attestation Key (AK)`
4. Client and Server perform TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
5. CLient and Server perform TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify) to ensure the server state is correct
6. Client requests an _Attested EC Key_ where the private key resides on the Server's TPM.
7. Client requests server for a locally signed `x509` certificate where the private key is the Attested EC key
8. Server issues the `x509` with a local CA (the ca can be an actual CA; this demo issues locally)
9. Server launches a new `HTTPS` server where the server certificate and private key are the newly issued x509 and TPM hosted EC private key
10. Client connects to the HTTPs server and compares the TLS sessions EC Public Key is the same as step step 6 (meaning its talking to that TPM's key)

Basically the `gRPC` server part (1->6) does some background steps to establish trust on the EC key.

After that, a new `HTTPS` server is launched which uses the EC Key on the TPM and a certificate signed by a local CA.

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [Kubernetes Trusted Platform Module (TPM) DaemonSet](https://github.com/salrashid123/tpm_daemonset)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
* [nginx with TPM based SSL](https://blog.salrashid.dev/articles/2021/nginx_with_tpm_ssl/)

so whats so good about this?  well, your client is _assured_ that they are terminating the TLS connection on that VM that includes that specific TPM.

Note the part where CA certificate (local or otherwise) issues the x509 (step 7) isn't the critical part in this flow:  the fact that the attested _EC Public Key matches whats in the certificate and TLS session is important_.  If you wanted, instead of the attestor's CA that issues the x509, the client could've done that given the attested public key and its own CA and then returned the x509 to the server which would then be used it to start the TLS-HTTP server.  (see example [here](https://gist.github.com/salrashid123/10320c153ad6acdc31854c9775c43c0d) on how to apply a attested public key to a cert)

---

>> NOTE: this repo and code is *not* supported by google

---

### Setup

Create a VM

```bash
gcloud compute instances create attestor   \
   --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
      --image-family=debian-11 --image-project=debian-cloud    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

gcloud compute firewall-rules create allow-tpm-verifier  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:50051

gcloud compute firewall-rules create allow-tpm-verifier-https  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:8081

$ gcloud compute instances list
NAME        ZONE           MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP     STATUS
attestor    us-central1-a  e2-medium                  10.128.0.58    35.193.185.190  RUNNING

export ATTESTOR_ADDRESS=35.193.185.190

# optionally if you installed TPM2_TOOLS, you can print the PCR value
# on the vm type above, PCR0 is
# tpm2_pcrread sha256:0
#  sha256:
#    0 : 0xD0C70A9310CD0B55767084333022CE53F42BEFBB69C059EE6C0A32766F160783
# alternatively, you can use go-tpm's pcrread: https://github.com/salrashid123/tpm2/tree/master/pcr_utils
```

SSH to the attestor, [install golang](https://go.dev/doc/install) and run

```bash
mkdir /tmp/contexts

git clone https://github.com/salrashid123/tls_ak.git
cd tls_ak/server

go run grpc_attestor.go --grpcport :50051 --v=10 -alsologtostderr
```


On the laptop, run the attestor

```bash
git clone https://github.com/salrashid123/tls_ak.git
cd tls_ak/client

go run grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
   --appaddress=$ATTESTOR_ADDRESS:8081 \
   --expectedPCRMapSHA256=0:d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783 \
    --v=10 -alsologtostderr
```


What you'll see in the output is the full remote attestation, then a certificate issued with a specific public key where the private key is on the TPM (and is attested by AK)


The client connects to the server and prints the public key....the fact the same public keys are shown confirms the attested key on the TPM is at the other end of the TLS session.

---

* `server`

```log
$ go run grpc_attestor.go --grpcport :50051 --v=20 -alsologtostderr

I0624 15:17:38.452574    2956 grpc_attestor.go:712] Getting EKCert reset
I0624 15:17:38.653516    2956 grpc_attestor.go:756] Starting gRPC server on port :50051
I0624 15:17:46.768566    2956 grpc_attestor.go:87] ======= GetEK ========
I0624 15:17:46.799590    2956 grpc_attestor.go:113] ======= GetAK ========
I0624 15:17:47.068745    2956 grpc_attestor.go:175] ======= Attest ========
I0624 15:17:47.241102    2956 grpc_attestor.go:228] ======= Quote ========
I0624 15:17:47.525942    2956 grpc_attestor.go:286] ======= NewKey ========
I0624 15:17:47.740185    2956 grpc_attestor.go:373] ======= Sign ========
I0624 15:17:47.815783    2956 grpc_attestor.go:443] ======= StartTLS ========
I0624 15:17:47.832655    2956 grpc_attestor.go:494]         Issuing Cert ========
I0624 15:17:47.849775    2956 grpc_attestor.go:559]       CSR 
-----BEGIN CERTIFICATE REQUEST-----
MIIBXTCCAQMCAQAwbzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzARBgNV
BAsTCkVudGVycHJpc2UxDDAKBgNVBAMTA2ZvbzBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABIlIYsXiNXhZ7l79cP90fskcDs0dvrls9wAypEaVryfKn4ze6xNjVL+U
Z1mlLP1dX/vfn9ybn48HJF7b1E0iQzmgMjAwBgkqhkiG9w0BCQ4xIzAhMB8GA1Ud
EQQYMBaCFGVjaG8uZXNvZGVtb2FwcDIuY29tMAoGCCqGSM49BAMCA0gAMEUCIQDL
pF+F2ZDOyoBzD5S/56RsYDPHXBaYqJH8AhHXC6DvjAIgCjPk1yLutvYqksT1gbdN
2+/r5f9MrVcs+LlzltitxCE=
-----END CERTIFICATE REQUEST-----

I0624 15:17:47.853616    2956 grpc_attestor.go:606]         cert Issuer CN=Enterprise Root CA,OU=Enterprise,O=Google,C=US
I0624 15:17:47.853702    2956 grpc_attestor.go:608]         Issued Certificate ========
-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIQDTtJ8O+XSbildJ5M+LPFnTANBgkqhkiG9w0BAQsFADBQ
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMRswGQYDVQQDDBJFbnRlcnByaXNlIFJvb3QgQ0EwHhcNMjMwNjI0MTUxNzQ3
WhcNMjQwNjIzMTUxNzQ3WjBvMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzET
MBEGA1UECxMKRW50ZXJwcmlzZTEMMAoGA1UEAxMDZm9vMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+uWz3ADKkRpWvJ8qfjN7r
E2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOaN3MHUwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
BmTI/lDbzru8PoYStdKMNtVIb9owHwYDVR0RBBgwFoIUZWNoby5lc29kZW1vYXBw
Mi5jb20wDQYJKoZIhvcNAQELBQADggEBALRf287T7bYJqBI3lqdEojHLnzvfmy8f
ZpxDEg2EoQKxblVPIfyxwsM2+q0Eui7mZGLd5sSeKBhnffsohr+rPQShNLfeu0qf
bbDITPOVrRF94vKOY32AvPnm7kYw1ihfZgbt/DNDVaEkP9+LYMc3e1pTjwBmnW4+
t0DeBMysTIAXyoAcUKirzBNvXYOttvxxrvIjzdhjF7nSE5n72igrkohJqD1vDUFB
fUvDCve3wuVhKTmEbnMssz7+gF1DPDDULbY9U4jbE7rKQBDPAMkPtv6i0onqr58n
jIoenq2yR67oBfniohtm+CJEW83e5Eu7D3rzoaEnKN8vN5gRhBu+WAA=
-----END CERTIFICATE-----

I0624 15:17:47.853893    2956 grpc_attestor.go:630]         Issued certificate tied to PubicKey ========
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+
uWz3ADKkRpWvJ8qfjN7rE2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOQ==
-----END PUBLIC KEY-----

I0624 15:17:47.853935    2956 grpc_attestor.go:648] Starting Server..
```

---

* `client`

```log
$ go run grpc_verifier.go --host $ATTESTOR_ADDRESS:50051 --appaddress=$ATTESTOR_ADDRESS:8081 --v=10 -alsologtostderr


I0624 11:17:46.656886  193116 grpc_verifier.go:93] =============== start GetEK ===============
I0624 11:17:46.788089  193116 grpc_verifier.go:187]      EKPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----

I0624 11:17:46.788128  193116 grpc_verifier.go:201] =============== end GetEKCert ===============
I0624 11:17:46.788138  193116 grpc_verifier.go:203] =============== start GetAK ===============
I0624 11:17:47.056191  193116 grpc_verifier.go:243]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww0IqO9aTrTEieJg8Y4u
7p5Q1bX7l+3AgEOkFKXWLL2qduVitOVIbWcnzkiQlra4EO81BjApr3dVd8PeK1ot
UCZqzhCk2oVzZlYWqJJkZSVWwaBwDe89kQwvgmOXmShXnEUdGmYANhVACFMqaIwR
HCLP2Vrs6x7x+7bs2syPEXV6Do82XKvY5dG48ktxCsmlHbQQlbLPmtIa7gDojRjQ
RhAPNrZTZDC6LFtZ2K8r6ioqali2+9Q4PCXXi8rEIUYYigWUmA352XDyLgYNivnc
JpyVcDcvMaT4A9Jaij0pps2So9KgiQi94H3QzS+y+c++st+nXLj8UUUbCwB0UA7Q
qwIDAQAB
-----END PUBLIC KEY-----

I0624 11:17:47.056237  193116 grpc_verifier.go:244] =============== end GetAK ===============
I0624 11:17:47.056250  193116 grpc_verifier.go:246] =============== start Attest ===============
I0624 11:17:47.056468  193116 grpc_verifier.go:252]       Outbound Secret: o+/MoLDXWDIBCzxwEMwQmzaCREHbW6LC4bzA+Y1GOkg=
I0624 11:17:47.227455  193116 grpc_verifier.go:269]       Inbound Secret: o+/MoLDXWDIBCzxwEMwQmzaCREHbW6LC4bzA+Y1GOkg=
I0624 11:17:47.227486  193116 grpc_verifier.go:272]       inbound/outbound Secrets Match; accepting AK
I0624 11:17:47.227499  193116 grpc_verifier.go:277] =============== end Attest ===============
I0624 11:17:47.227511  193116 grpc_verifier.go:279] =============== start Quote/Verify ===============
I0624 11:17:47.513492  193116 grpc_verifier.go:325]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww0IqO9aTrTEieJg8Y4u
7p5Q1bX7l+3AgEOkFKXWLL2qduVitOVIbWcnzkiQlra4EO81BjApr3dVd8PeK1ot
UCZqzhCk2oVzZlYWqJJkZSVWwaBwDe89kQwvgmOXmShXnEUdGmYANhVACFMqaIwR
HCLP2Vrs6x7x+7bs2syPEXV6Do82XKvY5dG48ktxCsmlHbQQlbLPmtIa7gDojRjQ
RhAPNrZTZDC6LFtZ2K8r6ioqali2+9Q4PCXXi8rEIUYYigWUmA352XDyLgYNivnc
JpyVcDcvMaT4A9Jaij0pps2So9KgiQi94H3QzS+y+c++st+nXLj8UUUbCwB0UA7Q
qwIDAQAB
-----END PUBLIC KEY-----

I0624 11:17:47.513723  193116 grpc_verifier.go:352]      quotes verified
I0624 11:17:47.514267  193116 grpc_verifier.go:365]      secureBoot State enabled true
I0624 11:17:47.514423  193116 grpc_verifier.go:371] =============== end Quote/Verify ===============
I0624 11:17:47.514443  193116 grpc_verifier.go:373] =============== start NewKey ===============
I0624 11:17:47.727775  193116 grpc_verifier.go:384]      newkey Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+
uWz3ADKkRpWvJ8qfjN7rE2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOQ==
-----END PUBLIC KEY-----
I0624 11:17:47.727993  193116 grpc_verifier.go:401]      new key verified
I0624 11:17:47.728023  193116 grpc_verifier.go:402] =============== end NewKey ===============
I0624 11:17:47.728048  193116 grpc_verifier.go:404] =============== start Sign ===============
I0624 11:17:47.803828  193116 grpc_verifier.go:417]      signature: MEUCIQCj35BdSkWcUx1iNWVua5hUlEMj3QrplZoFMxLvbmdX1AIgVpvT5fCHUYog6YW2HAw4FagL/gdm18yLMmdTg1fyatE=
I0624 11:17:47.804061  193116 grpc_verifier.go:441]      signature verified
I0624 11:17:47.804095  193116 grpc_verifier.go:442] =============== end Sign ===============
I0624 11:17:47.804129  193116 grpc_verifier.go:444] =============== start StartTLS ===============
I0624 11:17:48.100736  193116 grpc_verifier.go:454]      startTLSResponse status true
I0624 11:17:48.100794  193116 grpc_verifier.go:456] =============== start http client ===============
I0624 11:17:48.212865  193116 grpc_verifier.go:494]       Issuer CN=Enterprise Root CA,OU=Enterprise,O=Google,C=US
I0624 11:17:48.213054  193116 grpc_verifier.go:507]      peer public key 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+
uWz3ADKkRpWvJ8qfjN7rE2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOQ==
-----END PUBLIC KEY-----

I0624 11:17:48.213125  193116 grpc_verifier.go:515] 200 OK
I0624 11:17:48.213170  193116 grpc_verifier.go:516] ok
```

Once the https server is running, you can continue to interact with it on port `:8081`

```bash
$ curl -vvv --cacert ../certs/issuer_ca.crt \
   --resolve  echo.esodemoapp2.com:8081:$ATTESTOR_ADDRESS https://echo.esodemoapp2.com:8081/

$ openssl s_client --connect $ATTESTOR_ADDRESS:8081
```

Note the certificate specifications and public key matches the attested EC public key that was tied to the TPM

```bash
$ openssl s_client -connect $ATTESTOR_ADDRESS:8081 | openssl x509 -pubkey -noout
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+
uWz3ADKkRpWvJ8qfjN7rE2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOQ==
-----END PUBLIC KEY-----

### or download and save the x509 cert to "a.crt":
$ openssl x509 -in a.crt -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0d:3b:49:f0:ef:97:49:b8:a5:74:9e:4c:f8:b3:c5:9d
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
        Validity
            Not Before: Jun 24 15:17:47 2023 GMT
            Not After : Jun 23 15:17:47 2024 GMT
        Subject: C = US, ST = California, L = Mountain View, O = Acme Co, OU = Enterprise, CN = foo
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:89:48:62:c5:e2:35:78:59:ee:5e:fd:70:ff:74:
                    7e:c9:1c:0e:cd:1d:be:b9:6c:f7:00:32:a4:46:95:
                    af:27:ca:9f:8c:de:eb:13:63:54:bf:94:67:59:a5:
                    2c:fd:5d:5f:fb:df:9f:dc:9b:9f:8f:07:24:5e:db:
                    d4:4d:22:43:39
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                06:64:C8:FE:50:DB:CE:BB:BC:3E:86:12:B5:D2:8C:36:D5:48:6F:DA
            X509v3 Subject Alternative Name: 
                DNS:echo.esodemoapp2.com
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        b4:5f:db:ce:d3:ed:b6:09:a8:12:37:96:a7:44:a2:31:cb:9f:
        3b:df:9b:2f:1f:66:9c:43:12:0d:84:a1:02:b1:6e:55:4f:21:
        fc:b1:c2:c3:36:fa:ad:04:ba:2e:e6:64:62:dd:e6:c4:9e:28:
        18:67:7d:fb:28:86:bf:ab:3d:04:a1:34:b7:de:bb:4a:9f:6d:
        b0:c8:4c:f3:95:ad:11:7d:e2:f2:8e:63:7d:80:bc:f9:e6:ee:
        46:30:d6:28:5f:66:06:ed:fc:33:43:55:a1:24:3f:df:8b:60:
        c7:37:7b:5a:53:8f:00:66:9d:6e:3e:b7:40:de:04:cc:ac:4c:
        80:17:ca:80:1c:50:a8:ab:cc:13:6f:5d:83:ad:b6:fc:71:ae:
        f2:23:cd:d8:63:17:b9:d2:13:99:fb:da:28:2b:92:88:49:a8:
        3d:6f:0d:41:41:7d:4b:c3:0a:f7:b7:c2:e5:61:29:39:84:6e:
        73:2c:b3:3e:fe:80:5d:43:3c:30:d4:2d:b6:3d:53:88:db:13:
        ba:ca:40:10:cf:00:c9:0f:b6:fe:a2:d2:89:ea:af:9f:27:8c:
        8a:1e:9e:ad:b2:47:ae:e8:05:f9:e2:a2:1b:66:f8:22:44:5b:
        cd:de:e4:4b:bb:0f:7a:f3:a1:a1:27:28:df:2f:37:98:11:84:
        1b:be:58:00



$ openssl x509 -pubkey -noout -in a.crt

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiUhixeI1eFnuXv1w/3R+yRwOzR2+
uWz3ADKkRpWvJ8qfjN7rE2NUv5RnWaUs/V1f+9+f3JufjwckXtvUTSJDOQ==
-----END PUBLIC KEY-----
```

---

Final note, GCE VMs also surface an API that returns the EKPub encryption (and signing/AK) keys:

compare the ekPub below against the ek returned by the server above:

```bash
$ gcloud compute instances get-shielded-identity attestor
encryptionKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
    tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
    ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
    WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
    ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
    BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
    uwIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr8f4lOUaHIMDoC9Baq
    sLs2Irh1RrKmTbgf/cWZHvhCQUT3qGGB5gqI96/efF3pCKx/KL9tYpJ7iQ3TpJhv
    E8sG+bfxA3qvoDXIzO8bsAPyEp6c77UfvHkasi4cKZP2kBIURy/TwOSeZco7qU51
    V10pL4kcw8J0CeDr4KKap6m4gWXcdo4rOpRMy62bBRIaxWEbPrAlotHSoD6hvtlT
    W0zBhs4zFrau+85YZNuobvvkPoZho/NosLKqNZ2gb2/ueY/mU0uAPhhtHtk7KWiN
    p5iSqcWHyrzU/tZ3LwiRB/vOxeQhWH3+o3BJPU0z9Dm+5fFlO6Se4hm1/S8VxYZ4
    owIDAQAB
    -----END PUBLIC KEY-----
```

Unfortunately, the `go-attestation` library i'm using does not easily surface the ekSigning key for attestation.  see [issue#334](https://github.com/google/go-attestation/issues/334)

As for RSA keys, it turns out the for TPMs, [rsa.PSSSaltLengthAuto](https://pkg.go.dev/crypto/rsa#PSSOptions) is used but whats provided via go1.17+ during TLS1.3 is  [PSSSaltLengthEqualsHash](https://pkg.go.dev/crypto/rsa#pkg-constants)...meaning its difficult to make RSA to work at the moment with go and TLS specifically. (for ref, see [tpm2-pkcs11/issues/417](https://github.com/tpm2-software/tpm2-pkcs11/issues/417))