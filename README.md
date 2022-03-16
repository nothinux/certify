# Certify
[![Go Report Card](https://goreportcard.com/badge/github.com/nothinux/certify)](https://goreportcard.com/report/github.com/nothinux/certify)  ![test status](https://github.com/nothinux/go-ps/actions/workflows/test.yml/badge.svg?branch=master)  
Certify can be used for creating a private CA (Certificate Authority) and issuing certificates signed by the pre-created CA.

Also, you can set subject alternative names (IP SAN and DNS SAN), common name and expiry date for the created certificate.

## Installation
Download in the [release page](https://github.com/nothinux/certify/releases)

## Usage
```
certify [flag] [ip-or-dns-san] [cn:default certify] [expiry: s,m,h,d]

$ certify -init
⚡️ Initialize new CA Certificate and Key

$ certify server.local 172.17.0.1
⚡️ Generate certificate with alt name server.local and 172.17.0.1

$ certify server.local expiry:1d
⚡️ Generate certificate expiry within 1 day

$ certify cn:web-server
⚡️ Generate certificate with common name web-server

Also, you can see information from created certificate

$ certify -show server.local.pem
⚡️ Show certificate information with filename server.local.pem

$ certify -connect google.com:443
⚡️ Show certificate information from remote host
```

## Use Certify as library
You can also use certify as library for your Go application

### Installation
```
go get github.com/nothinux/certify
```
### Documentation
see [pkg.go.dev](https://pkg.go.dev/github.com/nothinux/go-ps)
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
