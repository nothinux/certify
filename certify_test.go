package certify

import (
	"crypto/x509/pkix"
	"net"
	"strings"
	"testing"
	"time"
)

var (
	RSATestCert = `-----BEGIN CERTIFICATE-----
MIIFUTCCBDmgAwIBAgIRAKXhAWONgQR0CqU9N56GVkcwDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxRDQwHhcNMjIwNDA5MTgxNzQ1WhcNMjIwNzA4
MTgxNzQ0WjARMQ8wDQYDVQQDEwZnby5kZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC+++2A2RSZe0t8HrdKME2l8fsRtdBm83NDrFjI+ljGxh+fFoxp
szy4nyseUpQFFthlns/9Z0LJSwRTdbxLDNQdiDxAyMsnt20Je1bsaUP4g1jDZ00e
UhsMOsIApiCs6DRFqHydBLZVeWMraGa4e2g8q/x7LD3G7sYoXfOb3/yYJeghPuPE
tEdYssVPzZmdB0zJYBQZTVCSH4ceiOrnfrV7tbXKYzhN/ZUhaKOA07y3Yu9WtgHK
+drf4rnLxXALUxXOn73KFxrT5V7CYsnCcgtoc2v7dAtXORwd/cyD1OkfiL+8y5L3
Ix/AxfahGrYoM5GwuUerrLJ9l0Jio40dyArNAgMBAAGjggJtMIICaTAOBgNVHQ8B
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQUoHUzYU6hibyjmKXIgVEib4VVoF0wHwYDVR0jBBgwFoAUJeIYDrJXkZQq
5dRdhpCD3lOzuJIweAYIKwYBBQUHAQEEbDBqMDUGCCsGAQUFBzABhilodHRwOi8v
b2NzcC5wa2kuZ29vZy9zL2d0czFkNC9KYUk3amVIU3hkQTAxBggrBgEFBQcwAoYl
aHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMWQ0LmRlcjARBgNVHREECjAI
ggZnby5kZXYwIQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAHWeQIFAzA8BgNV
HR8ENTAzMDGgL6AthitodHRwOi8vY3Jscy5wa2kuZ29vZy9ndHMxZDQvRFlDVzlo
TnpyWHcuY3JsMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYAUaOw9f0BeZxWbbg3
eI8MpHrMGyfL956IQpoN/tSLBeUAAAGAD8z3swAABAMARzBFAiEAon8amRM09Pdm
mTr8RhSUljNjDyh2HktHIHksuMqP9XkCIDJ0vmMjT8AAtODewy1CQfKY6MBLRzOc
MX3pcNREwk9JAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUcAAAGA
D8z35gAABAMARzBFAiA1ylRik7z+2AOIdV+WNKjm4ui5/O3jmOAf2KCofz9SAgIh
AMGoUjsi2x/ODEvJ5qG/NLgtNwjVzMUZ6cCuUOsAECyHMA0GCSqGSIb3DQEBCwUA
A4IBAQA9kJTuv18L6fXMZwysP4tf5R7Wzu4tUhzVVQqnakLXt6lE4WuQGSRJGg+j
JvC+MLkTBXJidmSUwOwofQVVWLKSgnMaF2CnvO+zpoWQ9j/xjM+UeDJTsOWJDqJr
u7brL9iz0L3zopxmj2OT76rAjpnKVim/Dcw77pO0SA6Y6T68HaDxyx/xQG35U4ko
g0J3x484NSLqNjnU4aGP/C8XKe4gLQR6k0OWm0fktd7pCEakrklyswsgoDG7rB50
VvjDmr0mWlzsr1CfdnA1TysPFiULaRCFYaWhA71Sa/doNd5nrtuMzNetmmYFtpzq
pAkvSpiE1H6RLeKYTqyIAGcui/Ah
-----END CERTIFICATE-----`
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

	t.Log(CertInfo(cert))
}

func TestCertInfoRSA(t *testing.T) {
	cert, err := ParseCertificate([]byte(RSATestCert))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(CertInfo(cert))
}

func TestCertInEmptyFile(t *testing.T) {
	_, err := ParseCertificate([]byte(""))
	if err != nil {
		if !strings.Contains(err.Error(), "can't decode CA cert file") {
			t.Fatal("error must be contain can't decode CA cert file")
		}
	}
}
