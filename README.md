
## TPM based TLS using Attested Keys

Sample demonstrating `TLS` where the private key resides on the server is first attested though [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

Basically,

1. The server starts with default TLS configuration using key files
2. Client contacts server over default TLS and request `Endorsement Public Key (EKPub)`
3. Client contacts server requesting `Attestation Key (AK)`
4. Client and Server perform TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
5. CLient and Server perform TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify) to ensure the server state is correct
6. Client requests an Attested EC Private Key where the private key resides on the Server's TPM.
7. Client requests server for a locally signed `x509` certificate where the private key is the Attested EC key
8. Server issues the `x509` with a local CA (the ca can be an actual CA; this demo issues locally)
7. Server launches an HTTPS server where the server certificate and private key are the issued x509 and TPM EC private key
8. Client connect to the HTTPs server and prints the EC Public Key bound to TLS

Basically the `gRPC` server part (1->7) does some background steps to establish trust on the EC key.

After that, a new `HTTPS` server is launched which uses the EC Key on the TPM and a certificate signed by a local CA certificate issuer.

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [Kubernetes Trusted Platform Module (TPM) DaemonSet](https://github.com/salrashid123/tpm_daemonset)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)

so whats so good about this?  well, your client is _assured_ that they are terminating the TLS connection on that VM that includes that specific TPM!  end-to-nd

---

### Setup

Create a VM and [install golang](https://go.dev/doc/install) on the VM

```bash
gcloud compute instances create attestor   \
   --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
      --image=debian-11-bullseye-v20211105 --image-project=debian-cloud    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

gcloud compute firewall-rules create allow-tpm-verifier  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:50051

gcloud compute firewall-rules create allow-tpm-verifier-https  --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:8081

$ gcloud compute instances list
NAME        ZONE           MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP     STATUS
attestor    us-central1-a  e2-medium                  10.128.0.58    35.193.185.190  RUNNING

# optionally if you installed TPM2_TOOLS, you can print the PCR value
# on the vm type above, PCR0 is
# tpm2_pcrread sha256:0
#  sha256:
#    0 : 0xD0C70A9310CD0B55767084333022CE53F42BEFBB69C059EE6C0A32766F160783
```

SSH to the attestor VM and run

```bash
mkdir /tmp/contexts
git clone https://github.com/salrashid123/mtls_ak.git
cd mtls_ak/
go run grpc_attestor.go --grpcport :50051 --v=10 -alsologtostderr
```


On the laptop, run the attestor

```bash
go run grpc_verifier.go --host 35.193.185.190:50051 --v=10 -alsologtostderr
```


What you'll see in the output is the full remote attestation, then a certificate issued with a specific public key where the private key is on the TPM (and is attested by AK)


The client connects to the server and prints the public key....the fact the same public keys 
---


* `server`

```log
$ go run grpc_attestor.go --grpcport :50051 --v=20 -alsologtostderr

I0624 03:34:55.289449   10415 grpc_attestor.go:660] Getting EKCert reset
I0624 03:34:55.488542   10415 grpc_attestor.go:704] Starting gRPC server on port :50051
I0624 03:35:06.525370   10415 grpc_attestor.go:94] ======= GetEK ========
I0624 03:35:06.556221   10415 grpc_attestor.go:120] ======= GetAK ========
I0624 03:35:06.843651   10415 grpc_attestor.go:182] ======= Attest ========
I0624 03:35:07.018779   10415 grpc_attestor.go:235] ======= Quote ========
I0624 03:35:07.321554   10415 grpc_attestor.go:293] ======= NewKey ========
I0624 03:35:07.556792   10415 grpc_attestor.go:380] ======= Sign ========
I0624 03:35:07.632598   10415 grpc_attestor.go:450] ======= StartTLS ========
I0624 03:35:07.649926   10415 grpc_attestor.go:496]         Issuing Selfsigned Cert ========
I0624 03:35:07.652647   10415 grpc_attestor.go:565] cert Issuer CN=Enterprise Root CA,OU=Enterprise,O=Google,C=US
I0624 03:35:07.652717   10415 grpc_attestor.go:567]         Issued Certificate ========
-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIQYjxof3PcqzwQ3F8LUtw/NzANBgkqhkiG9w0BAQsFADBQ
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMRswGQYDVQQDDBJFbnRlcnByaXNlIFJvb3QgQ0EwHhcNMjMwNjI0MDMzNTA3
WhcNMjQwNjIzMDMzNTA3WjBvMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzET
MBEGA1UECxMKRW50ZXJwcmlzZTEMMAoGA1UEAxMDZm9vMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEnw3dIh4lCpRyFeawrjCQZAIrT+NhoYPhGA4osPXy6fKdwZ88
oTqaJ7JpNx2a1k0GBs4l9XFOq2SXhLqBCOVtk6N3MHUwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
BmTI/lDbzru8PoYStdKMNtVIb9owHwYDVR0RBBgwFoIUZWNoby5lc29kZW1vYXBw
Mi5jb20wDQYJKoZIhvcNAQELBQADggEBAF8ukZWnYiaDMnPFR6Cl2XA1KapKWL/+
JJk+DjshLjR7T6GlT1y/So/MuzFCw30HTrh2MW0CJcDmEk+CCoCy7YKDmhIravyi
wXmIQ8LfSgm5CvSRPe9botBjlJIqoQLa4AvB1dSLjIIyPqwMTDGfv/Ii7lPBx064
42X4ZXJZeprej/V9nB3rTK2hZHna5K15UyjAuuAejiTOwajekNbY0xwxNW+459DU
Eqe2KklgRtujzDIf+uWXMVUyOPD5ruzxWOfRBqsJfknIA1W0x8PTi8QoWOhk3Eav
LiR9OEaKL7We1q7ezAU70eoRu9hxeZg6V2WKEvo1g7eMUZlZ+T5aMZk=
-----END CERTIFICATE-----

I0624 03:35:07.652900   10415 grpc_attestor.go:586]         Issued certificate tied to PubicKey ========
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnw3dIh4lCpRyFeawrjCQZAIrT+Nh
oYPhGA4osPXy6fKdwZ88oTqaJ7JpNx2a1k0GBs4l9XFOq2SXhLqBCOVtkw==
-----END EC PUBLIC KEY-----

I0624 03:35:07.652939   10415 grpc_attestor.go:604] Starting Server..
```

---

* `client`

```log
$ go run grpc_verifier.go --host 35.193.185.190:50051 --appaddress=35.193.185.190:8081 --v=10 -alsologtostderr


I0623 23:35:06.408432   89360 grpc_verifier.go:93] =============== start GetEK ===============
I0623 23:35:06.543085   89360 grpc_verifier.go:187]      EKPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLLB37zQTi3KfKridPpY
tj9yKm0ci/QUGqrzBsVVqxqOsQUxocsaKMZPIO7VxJlJd8KHWMoGY6f1VOdNUFCN
ufg5WMqA/t6rXvjF4NtPTvR05dCV4JegBBDnOjF9NgmV67+NgAm3afq/Z1qvJ336
WUop2prbTWpseNtdlp2+4TOBSsNZgsum3CFr40qIsa2rb9xFDrqoMTVkgKGpJk+z
ta+pcxGXYFJfU9sb7F7cs3e+TzjucGFcpVEiFzVq6Mga8cmh32sufM/PuifVYSLi
BYV4s4c53gVq7v0Oda9LqaxT2A9EmKopcWUU8CEgbsBxhmVAhsnKwLDmJYKULkAk
uwIDAQAB
-----END PUBLIC KEY-----

I0623 23:35:06.543179   89360 grpc_verifier.go:201] =============== end GetEKCert ===============
I0623 23:35:06.543208   89360 grpc_verifier.go:203] =============== start GetAK ===============
I0623 23:35:06.828462   89360 grpc_verifier.go:243]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3ECQzDmSmrC1nBC98IT
C/2T2nXj9/ZefwoToeMRvxhqoS2ipfccYsVlWVgpOiiHt1QuN8TnKJmUlpVFUcy7
a+TQQeJ7tMEgp9h2bOu/6HEbi9iZvVKyU+0OUEJAGYB1rre/DTi1YV27Dks/X26g
XuIpp0QTXqklKEbvbJMvpb3rKf20rvHlePfZe3D3Vgmx6q2CtXPA4/N+bB5y0CJx
f88EtVIsl1rwI7q7EI1aHHl2fhoHbTWR1uxWDs99Q923QI/qwTh9WVRt+KkOXX/B
TCctCK/mP/8D8VDBjimMTQ4OqQBpaBHtIMhsa9umKb/l/J7aH9USk9mN8rvwQQYs
GQIDAQAB
-----END PUBLIC KEY-----

I0623 23:35:06.828531   89360 grpc_verifier.go:244] =============== end GetAK ===============
I0623 23:35:06.828564   89360 grpc_verifier.go:246] =============== start Attest ===============
I0623 23:35:06.829104   89360 grpc_verifier.go:252]       Outbound Secret: FxaHa7HefmCRM5gVhQxz+EjQSr24nYV5bD1LTtCjKuo=
I0623 23:35:07.003439   89360 grpc_verifier.go:269]       Inbound Secret: FxaHa7HefmCRM5gVhQxz+EjQSr24nYV5bD1LTtCjKuo=
I0623 23:35:07.003504   89360 grpc_verifier.go:272]       inbound/outbound Secrets Match; accepting AK
I0623 23:35:07.003539   89360 grpc_verifier.go:277] =============== end Attest ===============
I0623 23:35:07.003571   89360 grpc_verifier.go:279] =============== start Quote/Verify ===============
I0623 23:35:07.304646   89360 grpc_verifier.go:325]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3ECQzDmSmrC1nBC98IT
C/2T2nXj9/ZefwoToeMRvxhqoS2ipfccYsVlWVgpOiiHt1QuN8TnKJmUlpVFUcy7
a+TQQeJ7tMEgp9h2bOu/6HEbi9iZvVKyU+0OUEJAGYB1rre/DTi1YV27Dks/X26g
XuIpp0QTXqklKEbvbJMvpb3rKf20rvHlePfZe3D3Vgmx6q2CtXPA4/N+bB5y0CJx
f88EtVIsl1rwI7q7EI1aHHl2fhoHbTWR1uxWDs99Q923QI/qwTh9WVRt+KkOXX/B
TCctCK/mP/8D8VDBjimMTQ4OqQBpaBHtIMhsa9umKb/l/J7aH9USk9mN8rvwQQYs
GQIDAQAB
-----END PUBLIC KEY-----

I0623 23:35:07.305273   89360 grpc_verifier.go:352]      quotes verified
I0623 23:35:07.306932   89360 grpc_verifier.go:365]      secureBoot State enabled true
I0623 23:35:07.307401   89360 grpc_verifier.go:371] =============== end Quote/Verify ===============
I0623 23:35:07.307461   89360 grpc_verifier.go:373] =============== start NewKey ===============
I0623 23:35:07.542698   89360 grpc_verifier.go:384]      newkey Public 
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnw3dIh4lCpRyFeawrjCQZAIrT+Nh
oYPhGA4osPXy6fKdwZ88oTqaJ7JpNx2a1k0GBs4l9XFOq2SXhLqBCOVtkw==
-----END EC PUBLIC KEY-----
I0623 23:35:07.543087   89360 grpc_verifier.go:401]      new key verified
I0623 23:35:07.543146   89360 grpc_verifier.go:402] =============== end NewKey ===============
I0623 23:35:07.543196   89360 grpc_verifier.go:404] =============== start Sign ===============
I0623 23:35:07.617127   89360 grpc_verifier.go:417]      signature: MEUCIEjYSVkOZnNsUlORCvV23YMItOra3758AFifToKz+MghAiEAikmI7rs/FCg8fwbUjsBBj74xRj40pj/y9L1xouWnJ84=
I0623 23:35:07.617505   89360 grpc_verifier.go:441]      signature verified
I0623 23:35:07.617569   89360 grpc_verifier.go:442] =============== end Sign ===============
I0623 23:35:07.617627   89360 grpc_verifier.go:444] =============== start Sign ===============
I0623 23:35:07.648797   89360 grpc_verifier.go:454]      startTLSResponse verified true
I0623 23:35:07.648896   89360 grpc_verifier.go:455]      startTLSResponse status:true
I0623 23:35:07.648986   89360 grpc_verifier.go:457] =============== start http client ===============
I0623 23:35:07.764814   89360 grpc_verifier.go:495]       Issuer CN=Enterprise Root CA,OU=Enterprise,O=Google,C=US
I0623 23:35:07.764971   89360 grpc_verifier.go:508]      peer public key 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnw3dIh4lCpRyFeawrjCQZAIrT+Nh
oYPhGA4osPXy6fKdwZ88oTqaJ7JpNx2a1k0GBs4l9XFOq2SXhLqBCOVtkw==
-----END PUBLIC KEY-----

I0623 23:35:07.765088   89360 grpc_verifier.go:516] 200 OK
I0623 23:35:07.765170   89360 grpc_verifier.go:517] ok
```