package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Certificate hold certificate information
type Certificate struct {
	SerialNumber     *big.Int
	Subject          pkix.Name
	NotBefore        time.Time
	NotAfter         time.Time
	IPAddress        []net.IP
	DNSNames         []string
	IsCA             bool
	Parent           *x509.Certificate
	ParentPrivateKey interface{}
	KeyUsage         x509.KeyUsage
	ExtentedKeyUsage []x509.ExtKeyUsage
	SubjectKeyId     []byte
}

// Result hold created certificate in []byte format
type Result struct {
	ByteCert []byte
	Cert     *x509.Certificate
}

// GetSerial returns serial and an error
func GetSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	return serial, nil
}

// SetTemplate set template for x509.Certificate from given Certificate struct
func (c *Certificate) SetTemplate() x509.Certificate {
	return x509.Certificate{
		SerialNumber:          c.SerialNumber,
		Subject:               c.Subject,
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		ExtKeyUsage:           c.ExtentedKeyUsage,
		KeyUsage:              c.KeyUsage,
		IsCA:                  c.IsCA,
		IPAddresses:           c.IPAddress,
		DNSNames:              c.DNSNames,
		BasicConstraintsValid: true,
		SubjectKeyId:          c.SubjectKeyId,
	}
}

// GetCertificate generate certificate and returns it in Result struct
func (c *Certificate) GetCertificate(pkey *ecdsa.PrivateKey) (*Result, error) {
	serial, err := GetSerial()
	if err != nil {
		return nil, err
	}

	c.SerialNumber = serial
	template := c.SetTemplate()

	if c.Parent == nil {
		c.Parent = &template
	}

	if c.ParentPrivateKey == nil {
		c.ParentPrivateKey = pkey
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, c.Parent, &pkey.PublicKey, c.ParentPrivateKey)
	if err != nil {
		return nil, err
	}

	return &Result{ByteCert: der, Cert: c.Parent}, nil
}

// String returns certificate in string format
func (r *Result) String() string {
	var w bytes.Buffer

	if err := pem.Encode(&w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r.ByteCert,
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

// CertInfo returns certificate information
func CertInfo(cert *x509.Certificate) string {
	var buf bytes.Buffer

	buf.WriteString("Certificate\n")
	buf.WriteString(fmt.Sprintf("%4sData:\n", ""))
	buf.WriteString(fmt.Sprintf("%8sVersion: %d\n", "", cert.Version))
	buf.WriteString(fmt.Sprintf("%8sSerial Number:\n%12s%v\n", "", "", formatKeyIDWithColon(cert.SerialNumber.Bytes())))
	buf.WriteString(fmt.Sprintf("%8sSignature Algorithm: %v\n", "", cert.SignatureAlgorithm))

	buf.WriteString(fmt.Sprintf("%8sIssuer: %v\n", "", strings.Replace(cert.Issuer.String(), ",", ", ", -1)))

	buf.WriteString(fmt.Sprintf("%8sValidity:\n", ""))
	buf.WriteString(fmt.Sprintf("%12sNotBefore: %v\n", "", cert.NotBefore.Format("Jan 2 15:04:05 2006 GMT")))
	buf.WriteString(fmt.Sprintf("%12sNotAfter : %v\n", "", cert.NotAfter.Format("Jan 2 15:04:05 2006 GMT")))

	buf.WriteString(fmt.Sprintf("%8sSubject: %v\n", "", strings.Replace(cert.Subject.String(), ",", ", ", -1)))

	buf.WriteString(fmt.Sprintf("%8sSubject Public Key Info:\n", ""))
	buf.WriteString(fmt.Sprintf("%12sPublic Key Algorithm: %v\n", "", cert.PublicKeyAlgorithm))
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		if ecdsakey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sPublic Key: (%d bit)\n", "", ecdsakey.Params().BitSize))
			buf.WriteString(fmt.Sprintf("%16sNIST Curve: %s\n", "", ecdsakey.Params().Name))
		}
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsakey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sRSA Public-Key: (%d bit)\n", "", rsakey.N.BitLen()))
			buf.WriteString(fmt.Sprintf("%16sExponent: %d (%#x)\n", "", rsakey.E, rsakey.E))
		}
	}

	buf.WriteString(fmt.Sprintf("%8sX509v3 extensions:\n", ""))
	if len(parseExtKeyUsage(cert.ExtKeyUsage)) != 0 {
		buf.WriteString(fmt.Sprintf("%12sX509v3 Extended Key Usage:\n", ""))
		buf.WriteString(fmt.Sprintf("%16s%v\n", "", parseExtKeyUsage(cert.ExtKeyUsage)))
	}
	buf.WriteString(fmt.Sprintf("%12sX509v3 Basic Constraints:\n", ""))
	buf.WriteString(fmt.Sprintf("%16sCA: %v\n", "", cert.IsCA))

	if len(cert.IPAddresses) != 0 || len(cert.DNSNames) != 0 {
		buf.WriteString(fmt.Sprintf("%12sX509v3 Subject Alternative Name:\n", ""))
		if len(cert.IPAddresses) != 0 {
			var ips []string
			for _, ip := range cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			buf.WriteString(fmt.Sprintf("%16sIP Address: %v\n", "", strings.Join(ips, ", ")))
		}
		if len(cert.DNSNames) != 0 {
			buf.WriteString(fmt.Sprintf("%16sDNS: %v\n", "", strings.Join(cert.DNSNames, ", ")))
		}
	}

	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %v\n", "", cert.SignatureAlgorithm))

	return buf.String()
}
