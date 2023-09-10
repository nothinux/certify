package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CertRevocationList hold certificate revocation list
type CertRevocationList struct {
	Byte []byte
}

// CreateCRL Create certificate revocation list
func CreateCRL(pkey *ecdsa.PrivateKey, caCert *x509.Certificate, crl *x509.RevocationList, nextUpdate time.Time) (*CertRevocationList, *big.Int, error) {
	crlNumber := time.Now().UTC().Format("20060102150405")
	num, _ := big.NewInt(0).SetString(crlNumber, 10)

	if crl == nil {
		crl = &x509.RevocationList{
			RevokedCertificates: []pkix.RevokedCertificate{},
		}
	}

	crl.Number = num
	crl.ThisUpdate = time.Now()
	crl.NextUpdate = nextUpdate

	crlByte, err := x509.CreateRevocationList(rand.Reader, crl, caCert, pkey)
	if err != nil {
		return nil, nil, err
	}

	return &CertRevocationList{Byte: crlByte}, num, nil
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

func ParseCRL(crl []byte) (*x509.RevocationList, error) {
	c, _ := pem.Decode(crl)
	if c == nil {
		return nil, fmt.Errorf("no pem data")
	}

	return x509.ParseRevocationList(c.Bytes)
}

func RevokeCertificate(crl []byte, cert *x509.Certificate, caCert *x509.Certificate, pkey *ecdsa.PrivateKey, nextUpdate time.Time) (*CertRevocationList, *big.Int, error) {
	crlF, err := ParseCRL(crl)
	if err != nil {
		return nil, nil, err
	}

	crlF.RevokedCertificateEntries = append(crlF.RevokedCertificateEntries, x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	})

	return CreateCRL(pkey, caCert, crlF, nextUpdate)

}

func CRLInfo(rl *x509.RevocationList) string {
	var buf bytes.Buffer

	buf.WriteString("Certificate Revocation List (CRL):\n")
	buf.WriteString(fmt.Sprintf("%4sVersion \n", ""))
	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %v\n", "", rl.SignatureAlgorithm))

	buf.WriteString(fmt.Sprintf("%4sIssuer: %v\n", "", strings.Replace(rl.Issuer.String(), ",", ", ", -1)))
	buf.WriteString(fmt.Sprintf("%8sLastUpdate: %v\n", "", rl.ThisUpdate.Format("Jan 2 15:04:05 2006 GMT")))
	buf.WriteString(fmt.Sprintf("%8sNextUpdate: %v\n", "", rl.NextUpdate.Format("Jan 2 15:04:05 2006 GMT")))

	buf.WriteString(fmt.Sprintf("%8sCRL Extensions:\n", ""))
	buf.WriteString(fmt.Sprintf("%12sX509v3 Authority Key Identifier:\n", ""))
	buf.WriteString(fmt.Sprintf("%16s%s\n", "", formatKeyIDWithColon(rl.AuthorityKeyId)))
	buf.WriteString(fmt.Sprintf("%12sX509v3 CRL Number:\n", ""))
	buf.WriteString(fmt.Sprintf("%16s%s\n", "", rl.Number))

	if len(rl.RevokedCertificateEntries) == 0 {
		buf.WriteString("No Revoked Certificates\n")
		return buf.String()
	}

	buf.WriteString("Revoked Certificates:\n")
	for _, rc := range rl.RevokedCertificateEntries {
		buf.WriteString(fmt.Sprintf("%4sSerial Number: %s\n", "", formatKeyIDWithColon(rc.SerialNumber.Bytes())))
		buf.WriteString(fmt.Sprintf("%8sRevocation Date: %s\n", "", rc.RevocationTime.Format("Jan 2 15:04:05 2006 GMT")))
	}

	return buf.String()
}
