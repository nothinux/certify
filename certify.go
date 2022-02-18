package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

type Certificate struct {
	Subject          pkix.Name
	NotBefore        time.Time
	NotAfter         time.Time
	IPAddress        []net.IP
	DNSNames         []string
	IsCA             bool
	Parent           *x509.Certificate
	ParentPrivateKey interface{}
}

type Result struct {
	Certificate []byte
}

// getSerial returns serial and an error
func GetSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	return serial, nil
}

// setTemplate set template for x509.Certificate from given Certificate struct
func (c *Certificate) SetTemplate(serial *big.Int) x509.Certificate {
	return x509.Certificate{
		SerialNumber: serial,
		Subject:      c.Subject,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		IsCA:                  c.IsCA,
		IPAddresses:           c.IPAddress,
		DNSNames:              c.DNSNames,
		BasicConstraintsValid: true,
	}
}

// GetCertificate generate certificate and returns it in Result struct
func (c *Certificate) GetCertificate(pkey *ecdsa.PrivateKey) (*Result, error) {
	serial, _ := GetSerial()

	template := c.SetTemplate(serial)

	if c.Parent == nil {
		c.Parent = &template
	}

	if c.ParentPrivateKey == nil {
		c.ParentPrivateKey = pkey
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, c.Parent, &pkey.PublicKey, c.ParentPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	return &Result{Certificate: der}, nil
}

// String returns certificate in string format
func (r *Result) String() string {
	var w bytes.Buffer

	if err := pem.Encode(&w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r.Certificate,
	}); err != nil {
		return ""
	}

	return w.String()
}

// ParseCertificate returns parsed certificate and error
func ParseCertificate(cert []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(cert)
	if p == nil {
		return nil, fmt.Errorf("can't decode CA cert file")
	}

	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}

	return c, nil
}
