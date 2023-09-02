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

	template := &Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   "certify",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		SubjectKeyId: ski[:],
		DNSNames:     []string{"github.com"},
		IPAddress: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	t.Run("Test Create CRL with cert that doesn't have keyUsage", func(t *testing.T) {
		caCert, err := template.GetCertificate(pkey.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = CreateCRL(pkey.PrivateKey, caCert.Cert)
		if err == nil {
			t.Fatalf("this should be error, because the cert doesn't have keyUsage")
		}
	})

	t.Run("Test Create CRL", func(t *testing.T) {
		template.KeyUsage = x509.KeyUsageCRLSign

		caCert, err := template.GetCertificate(pkey.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = CreateCRL(pkey.PrivateKey, caCert.Cert)
		if err != nil {
			t.Fatal(err)
		}
	})
}
