package certify

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

func TestCreateCRL(t *testing.T) {
	pkey, err := GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := x509.MarshalPKIXPublicKey(&pkey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ski := sha1.Sum(b)

	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   "certify",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCRLSign,
		SubjectKeyId: ski[:],
		DNSNames:     []string{"github.com"},
		IPAddress: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	caCert, err := template.GetCertificate(pkey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateCRL(pkey.PrivateKey, caCert.Cert)
	if err != nil {
		t.Fatal(err)
	}
}
