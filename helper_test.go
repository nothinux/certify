package certify

import (
	"crypto/x509"
	"os"
	"reflect"
	"testing"
)

func TestGetPublicKey(t *testing.T) {
	expectedPubKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+aysjyEIsevJ5ZzTDPOutsBeGiG
ox8WdlL3mozzen8QcdQ7jKiLgtJmFme8+E9gb5K3goFmPaaplizqd/yxNA==
-----END PUBLIC KEY-----
`

	cert, err := readCertificateFile("./cmd/certify/testdata/ca-cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	pubkey, err := GetPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if pubkey != expectedPubKey {
		t.Fatalf("got %v, want %v", pubkey, expectedPubKey)
	}
}

func TestParseKeyUsage(t *testing.T) {
	tests := []struct {
		Name     string
		KeyUsage x509.KeyUsage
		Expected []string
	}{
		{
			Name:     "Test Cert Sign and CRL Sign Key Usage",
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			Expected: []string{"Cert Sign", "CRL Sign"},
		},
		{
			Name:     "Test CRL Sign Key Usage",
			KeyUsage: x509.KeyUsageCRLSign,
			Expected: []string{"CRL Sign"},
		},
		{
			Name:     "Test Digital Signature Key Usage",
			KeyUsage: x509.KeyUsageDigitalSignature,
			Expected: []string{"Digital Signature"},
		},
		{
			Name:     "Test other Key Usage",
			KeyUsage: x509.KeyUsage(0),
			Expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got := parseKeyUsage(tt.KeyUsage)
			if !reflect.DeepEqual(got, tt.Expected) {
				t.Fatalf("got %v, want %v", got, tt.Expected)
			}
		})
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	t.Run("Test single eku", func(t *testing.T) {
		result := parseExtKeyUsage([]x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		})

		expectedResult := "TLS Web Server Authentication"

		if result != expectedResult {
			t.Fatalf("got %v, eant %v", result, expectedResult)
		}
	})

	t.Run("Test multiple eku", func(t *testing.T) {
		result := parseExtKeyUsage([]x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		})

		expectedResult := "TLS Web Server Authentication, TLS Web Client Authentication"

		if result != expectedResult {
			t.Fatalf("got %v, eant %v", result, expectedResult)
		}
	})

	t.Run("Test all Eku", func(t *testing.T) {
		result := parseExtKeyUsage([]x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageIPSECEndSystem,
			x509.ExtKeyUsageIPSECTunnel,
			x509.ExtKeyUsageIPSECUser,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageOCSPSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageNetscapeServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		})

		expectedResult := "TLS Web Server Authentication, TLS Web Client Authentication, Any Extended Key Usage, Code Signing, E-mail Protection, IPSec End System, IPSec Tunnel, IPSec User, Time Stamping, OCSP Signing, Microsoft Server Gated Crypto, Netscape Server Gated Crypto, Microsoft Commercial Code Signing, 1.3.6.1.4.1.311.61.1.1"

		if result != expectedResult {
			t.Fatalf("got %v, eant %v", result, expectedResult)
		}
	})
}

func TestFormatKeyIDWithColon(t *testing.T) {
	result := formatKeyIDWithColon([]byte{36, 44, 106, 165, 22, 233, 173, 100, 28, 6, 69, 211, 74, 214, 212, 162})
	expectedResult := "24:2c:6a:a5:16:e9:ad:64:1c:06:45:d3:4a:d6:d4:a2"

	if result != expectedResult {
		t.Fatalf("got %v, want %v", result, expectedResult)
	}
}

func readCertificateFile(path string) (*x509.Certificate, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c, err := ParseCertificate(f)
	if err != nil {
		return nil, err
	}

	return c, nil
}
