package certify

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

var (
	CRLDATA = `-----BEGIN X509 CRL-----
MIHiMIGJAgEBMAoGCCqGSM49BAMCMCQxEDAOBgNVBAoTB2NlcnRpZnkxEDAOBgNV
BAMTB2NlcnRpZnkXDTIzMDkwMjE1NDAyNFoXDTIzMDkwNDE1NDAyNFqgNDAyMB8G
A1UdIwQYMBaAFB/nlGRBJw24im6iHRMrXXmExBnxMA8GA1UdFAQIAgYSZl+8gygw
CgYIKoZIzj0EAwIDSAAwRQIgah2RIGIppWkG2GJoYk+V+imapbQbmuq6ZtMqIcYw
s8wCIQD7qx8oS5eE8Zhwe7Sc3rUvZn1o0NNYrc6kkvwoXAzHwQ==
-----END X509 CRL-----
`
	CRLDATAWITHREVOCATIONCERT = `-----BEGIN X509 CRL-----
MIICyzCBtAIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhub3RoaW51eBcN
MjMwOTAyMTYyODQ2WhcNMjUwOTAxMTYyODQ2WjBIMCICEQCV3atQTTX3B6j9MM5p
JKwAFw0yMzA5MDIxMTE5MDZaMCICEQCTD91VR4f01/4pCuo+3AfIFw0yMzA5MDIx
NjI4NDZaoCMwITAfBgNVHSMEGDAWgBRwJ198tLFEwrc/2hvRwVgiBFGM6zANBgkq
hkiG9w0BAQsFAAOCAgEAeGiqXjlTE3Kgm6dwgZpQk5AhvX1raM+IC/4bgAeAQBJ5
6iGboGbW4mOaLFPPdawFJbmtRtyW2/RxQX2QW+/DwR/pPQ5IcYyNJ8gsyn/vpBZe
0zTOCg0ILBtWxa+YL4EYPk8EqiOMXVZG73qaJBUR4snRCwph3f1CI5PZvsgZaPmd
Q9X+tHYqHKruS/fu3uzAKgRUz27DCKgJ2kmPxF9AZ61J3PywykE8/A3ccLBHOzj+
IETKvuyWaATse2Q9qa1eDmjMDbZSpA4gQmSoCqOFc9M1exrb4zxT1YEwkosyzMvM
/6BbDdWd178Vjxlzy1MakOU+4IRV6X+n74zXRbaERypLJMWIy1ndHMsfDDYn0Hrc
1XXoEIkuc4wvFihFkN9PjEJBEo1Mraew9xe3x7NY7AD8fYW2JOgd+Z2vxlbqXQ9Z
nc4yytlA/P6hFJSbrigVAcUwQYPjS84DwLDFvJSmv0PpLiw0Enqdta4WcSOp/rr+
s3hycfohM1EtWm2GpmukKdJ6GkP3YitXnZo/FQOt6+0chmec3QYCrSiY1QHBEvX3
ty4YcAH77NN3m1GMbC62GfjWd70V/SK43kzBtIwGE+kkoWIPoZQj0tf/1ZrNFGKS
gkSyWaYiSbs9Xyl4ilVsENNxKsN5RUwv91ZisniYV5COfrJAsye3Jbzeb/AEGNM=
-----END X509 CRL-----`
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
		SubjectKeyId: ski[:],
		DNSNames:     []string{"github.com"},
		IPAddress: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	t.Run("Test Create CRL with cert that doesn't have keyUsage", func(t *testing.T) {
		template1 := template

		caCert, err := template1.GetCertificate(pkey.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = CreateCRL(pkey.PrivateKey, caCert.Cert, nil)
		if err == nil {
			t.Fatalf("this should be error, because the cert doesn't have keyUsage")
		}
	})

	t.Run("Test Create CRL", func(t *testing.T) {
		template2 := template
		template2.KeyUsage = x509.KeyUsageCRLSign

		caCert, err := template2.GetCertificate(pkey.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = CreateCRL(pkey.PrivateKey, caCert.Cert, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestParseCRL(t *testing.T) {
	rl, err := ParseCRL([]byte(CRLDATA))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Test CRL number output", func(t *testing.T) {
		if rl.Number.String() != "20230902154024" {
			t.Fatal("The CRL number is different from what we expect")
		}
	})
}

func TestCRLInfo(t *testing.T) {
	t.Run("Test CRL info with empty revocation list", func(t *testing.T) {
		rl, err := ParseCRL([]byte(CRLDATA))
		if err != nil {
			t.Fatal(err)
		}

		CRLInfo(rl)
	})

	t.Run("Test CRL info with 2 revocation list", func(t *testing.T) {
		rl, err := ParseCRL([]byte(CRLDATAWITHREVOCATIONCERT))
		if err != nil {
			t.Fatal(err)
		}

		CRLInfo(rl)
	})
}
