# :lock: Certify
Certify is an easy-to-use certificate manager and can be used as an alternative to OpenSSL. With Certify you can create your own private CA (Certificate Authority) and issue certificates with your own CA.

[![Go Reference](https://pkg.go.dev/badge/github.com/nothinux/certify.svg)](https://pkg.go.dev/github.com/nothinux/certify)  [![Go Report Card](https://goreportcard.com/badge/github.com/nothinux/certify)](https://goreportcard.com/report/github.com/nothinux/certify)  ![test status](https://github.com/nothinux/certify/actions/workflows/test.yml/badge.svg?branch=master)  [![codecov](https://codecov.io/gh/nothinux/certify/branch/master/graph/badge.svg?token=iR3c5Zwo3F)](https://codecov.io/gh/nothinux/certify)  

## Feature
+ Create a CA and intermediate CA
+ Issue certificate with custom common name, ip san, dns san, expiry date, and extended key usage
+ Show certificate information from file or remote host
+ Export certificate to PKCS12 format
+ Verify private key matches with certificate


## Installation
Download in the [release page](https://github.com/nothinux/certify/releases)

## Usage
```
             _   _ ___     
 ___ ___ ___| |_|_|  _|_ _ 
|  _| -_|  _|  _| |  _| | |
|___|___|_| |_| |_|_| |_  |
                      |___| Certify v1.5

Usage of certify:  
certify [flag] [ip-or-dns-san] [cn:default certify] [eku:default serverAuth,clientAuth] [expiry:default 8766h s,m,h,d]

$ certify server.local 172.17.0.1 cn:web-server eku:serverAuth expiry:1d

Flags:
  -init
        Initialize new root CA Certificate and Key
  -intermediate
        Generate intermediate certificate
  -read  <filename>
        Read certificate information from file server.local.pem
  -connect  <host:443> <tlsver:1.2>
        Show certificate information from remote host
  -export-p12  <cert> <private-key> <ca-cert>
        Generate client.p12 pem file containing certificate, private key and ca certificate
  -match  <private-key> <cert>
        Verify cert-key.pem and cert.pem has same public key
  -version
        print certify version
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
