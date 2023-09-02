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

// CreateCRL Create certificate revocation list
func CreateCRL(pkey *ecdsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	crlNumber := time.Now().UTC().Format("20060102150405")
	num, _ := big.NewInt(0).SetString(crlNumber, 10)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{},
		Number:              num,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Hour * 48),
	}, caCert, pkey)
	if err != nil {
		return "", err
	}

	var w bytes.Buffer
	if err := pem.Encode(&w, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	}); err != nil {
		return "", err
	}

	return w.String(), nil
}
