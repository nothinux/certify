# Certify
[![Go Report Card](https://goreportcard.com/badge/github.com/nothinux/certify)](https://goreportcard.com/report/github.com/nothinux/certify)  ![test status](https://github.com/nothinux/go-ps/actions/workflows/test.yml/badge.svg?branch=master)  
Certify can be used for creating a private CA (Certificate Authority) and issuing certificates signed by the pre-created CA.

Certify is easy to use and can be used as an alternative to OpenSSL.

## Feature
+ Create a certificate authorities
+ Issue certificate with custom common name, ip san, dns san, and expiry date
+ Show certificate information from file or remote host
+ Export certificate to PKCS12 format
+ Verify private key matches with certificate


## Installation
Download in the [release page](https://github.com/nothinux/certify/releases)

## Usage
```
certify [flag] [ip-or-dns-san] [cn:default certify] [expiry: s,m,h,d]

$ certify -init
⚡️ Initialize new CA Certificate and Key

You must create new CA by run -init before you can create certificate.

$ certify server.local 172.17.0.1
⚡️ Generate certificate with alt name server.local and 172.17.0.1

$ certify cn:web-server
⚡️ Generate certificate with common name web-server

$ certify server.local expiry:1d
⚡️ Generate certificate expiry within 1 day

Also, you can see information from certificate

$ certify -read server.local.pem
⚡️ Read certificate information from file server.local.pem

$ certify -connect google.com:443
⚡️ Show certificate information from remote host

Export certificate and private key file to pkcs12 format
$ certify -export-p12 cert.pem cert-key.pem ca-cert.pem
⚡️ Generate client.p12 pem file containing certificate, private key and ca certificate

Verify private key matches a certificate
$ certify -match cert-key.pem cert.pem
⚡️ verify cert-key.pem and cert.pem has same public key
```

## Use Certify as library
You can also use certify as library for your Go application

### Installation
```
go get github.com/nothinux/certify
```
### Documentation
see [pkg.go.dev](https://pkg.go.dev/github.com/nothinux/certify)
### Example
#### Create Private Key and CA Certificates
``` go
package main

import (
	"crypto/x509/pkix"
	"log"
	"os"
	"time"

	"github.com/nothinux/certify"
)

func main() {
	p, err := certify.GetPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("CA-key.pem", []byte(p.String()), 0640); err != nil {
		log.Fatal(err)
	}

	// create ca
	template := certify.Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(8766 * time.Hour),
		IsCA:      true,
	}

	caCert, err := template.GetCertificate(p.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("CA-cert.pem", []byte(caCert.String()), 0640); err != nil {
		log.Fatal(err)
	}

}

```

## License
[MIT](https://github.com/nothinux/certify/blob/master/LICENSE)
