package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// CertRevocationList hold certificate revocation list
type CertRevocationList struct {
	Byte []byte
}

// CreateCRL Create certificate revocation list
func CreateCRL(pkey *ecdsa.PrivateKey, caCert *x509.Certificate) (*CertRevocationList, error) {
	crlNumber := time.Now().UTC().Format("20060102150405")
	num, _ := big.NewInt(0).SetString(crlNumber, 10)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{},
		Number:              num,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Hour * 48),
	}, caCert, pkey)
	if err != nil {
		return nil, err
	}

	return &CertRevocationList{Byte: crl}, nil
}

// String return string of certificate revocation list in pem encoded format
func (c *CertRevocationList) String() string {
	var w bytes.Buffer
	if err := pem.Encode(&w, &pem.Block{
		Type:  "X509 CRL",
		Bytes: c.Byte,
	}); err != nil {
		return ""
	}

	return w.String()
}
