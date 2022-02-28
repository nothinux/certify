# Certify
[![Go Report Card](https://goreportcard.com/badge/github.com/nothinux/certify)](https://goreportcard.com/report/github.com/nothinux/certify)  ![test status](https://github.com/nothinux/go-ps/actions/workflows/test.yml/badge.svg?branch=master)  
Certify can be used for creating a private CA (Certificate Authority) and issuing certificates signed by the pre-created CA. Issued certificate will be active for 1 year.

Also, you can set subject alternative names (IP SAN and DNS SAN) and common name for the created certificate.

## Installation
Download in the [release page](https://github.com/nothinux/certify/releases)

## Usage
```
$ certify -init
⚡️ Initialize new CA Certificate and Key

$ certify server.local 172.17.0.1
⚡️ Generate certificate with alt name server.local and 172.17.0.1

$ certify cn:web-server
⚡️ Generate certificate with common name web-server
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
