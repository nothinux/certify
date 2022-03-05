package certify

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestGetCertificate(t *testing.T) {
	pkey, err := GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   "certify",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		IsCA:      true,
		DNSNames:  []string{"github.com"},
		IPAddress: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	cert, err := template.GetCertificate(pkey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Test created certificate match with given information", func(t *testing.T) {
		c, err := ParseCertificate([]byte(cert.String()))
		if err != nil {
			t.Fatal(err)
		}

		if c.Subject.CommonName != "certify" {
			t.Fatalf("got %v, want certify", c.Subject.CommonName)
		}

		if c.Subject.Organization[0] != "certify" {
			t.Fatalf("got %v, want certify", c.Subject.Organization[0])
		}

		if !c.IsCA {
			t.Fatal("IsCA must be true")
		}

		if c.DNSNames[0] != "github.com" {
			t.Fatalf("got %v, want github.com", c.DNSNames[0])
		}

		if c.IPAddresses[0].String() != "127.0.0.1" {
			t.Fatalf("got %v, want 127.0.0.1", c.IPAddresses[0].String())
		}

		tomorrow := time.Now().Add(24 * time.Hour)

		if c.NotAfter.Day() != tomorrow.Day() {
			t.Fatalf("got %v, want %v", c.NotAfter.Day(), tomorrow.Day())
		}

	})

}

func TestCertInfo(t *testing.T) {
	pkey, err := GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   "certify",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		IsCA:      true,
		DNSNames:  []string{"github.com"},
		IPAddress: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	res, err := template.GetCertificate(pkey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ParseCertificate([]byte(res.String()))
	if err != nil {
		t.Fatal(err)
	}

	s := CertInfo(cert)
	fmt.Println(s)
}
