package main

import (
	"log"
	"os"
	"strings"
	"testing"
)

var TestCertificate = `-----BEGIN CERTIFICATE-----
MIIBmDCCAT2gAwIBAgIQUjIMhHGW4CreYEIQOnPDdDAKBggqhkjOPQQDAjAkMRAw
DgYDVQQKEwdjZXJ0aWZ5MRAwDgYDVQQDEwdjZXJ0aWZ5MB4XDTIyMDMxNzA4NDQx
MloXDTIzMDMxNzE0NDQxMlowJDEQMA4GA1UEChMHY2VydGlmeTEQMA4GA1UEAxMH
Y2VydGlmeTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIPmsrI8hCLHryeWc0wz
zrrbAXhohqMfFnZS95qM83p/EHHUO4yoi4LSZhZnvPhPYG+St4KBZj2mqZYs6nf8
sTSjUTBPMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBTuUKyfBpn78BTa2fodsucBYuApejAKBggqhkjOPQQD
AgNJADBGAiEAlYCxixkXh6eI1nHBAhaUHajYF6ZWpK4tiDCWR5lHIA0CIQCpgqUp
+R8a3HBTIcrpgdoI2g11HmV9+qOysbuWNpTnMw==
-----END CERTIFICATE-----`

func TestInitCA(t *testing.T) {
	tests := []struct {
		Name       string
		Args       []string
		expectedCN string
	}{
		{
			Name:       "Test run -init without cn",
			Args:       []string{"certify", "-init"},
			expectedCN: "certify",
		},
		{
			Name:       "Test run -init with wrong cn format",
			Args:       []string{"certify", "-init", "cn-nothinux"},
			expectedCN: "certify",
		},
		{
			Name:       "Test run -init with other argument",
			Args:       []string{"certify", "-init", "cert"},
			expectedCN: "certify",
		},
		{
			Name:       "Test run -init with 4 argument",
			Args:       []string{"certify", "-init", "cert", "cn:aaa"},
			expectedCN: "aaa",
		},
		{
			Name:       "Test run -init with cn",
			Args:       []string{"certify", "-init", "cn:nothinux"},
			expectedCN: "nothinux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if err := initCA(tt.Args); err != nil {
				t.Fatal(err)
			}

			t.Run("Test parse certificate", func(t *testing.T) {
				cert, err := getCACert(caPath)
				if err != nil {
					t.Fatal(err)
				}

				if cert.Subject.CommonName != tt.expectedCN {
					t.Fatalf("got %v, want %v", cert.Subject.CommonName, tt.expectedCN)
				}
			})

			t.Cleanup(func() {
				os.Remove(caPath)
				os.Remove(caKeyPath)
			})
		})
	}
}

func getTestCertificate(filename string) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		log.Fatal(err)
	}

	os.Stdin = f

	return os.Stdin
}

func TestReadCertificate(t *testing.T) {
	// TODO: add test reading certificate from stdin
	tests := []struct {
		Name           string
		Args           []string
		Stdin          *os.File
		expectedOutput string
		expectedError  string
	}{
		{
			Name:           "Test read certificate from file",
			Args:           []string{"certify", "-read", "testdata/ca-cert.pem"},
			Stdin:          nil,
			expectedOutput: "Issuer: CN=certify, O=certify",
		},
		{
			Name:          "Test read not exists certificate",
			Args:          []string{"certify", "-read", "ca-cert.pem"},
			Stdin:         nil,
			expectedError: "open ca-cert.pem: no such file or directory",
		},
		{
			Name:          "Test read content from stdin",
			Args:          []string{"certify", "-read"},
			Stdin:         getTestCertificate("testdata/empty"),
			expectedError: "can't decode CA cert file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			cert, err := readCertificate(tt.Args, tt.Stdin)

			if err != nil {
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Fatalf("got %v, want %v", err, tt.expectedError)
				}
			}

			if !strings.Contains(cert, tt.expectedOutput) {
				t.Fatalf("error, want output %s", tt.expectedOutput)
			}

			if tt.Stdin != nil {
				tt.Stdin.Close()
			}
		})
	}
}

func TestReadRemoteCertificate(t *testing.T) {
	tests := []struct {
		Name           string
		Args           []string
		ExpectedOutput string
		ExpectedError  string
	}{
		{
			Name:           "Test valid Host",
			Args:           []string{"certify", "-connect", "google.com:443"},
			ExpectedOutput: "Subject: CN=*.google.com",
		},
		{
			Name:          "Test invalid Host",
			Args:          []string{"certify", "-connect", "google.com"},
			ExpectedError: "missing port in address",
		},
		{
			Name:          "Test invalid Host",
			Args:          []string{"certify", "-connect", "google"},
			ExpectedError: "missing port in address",
		},
		{
			Name:          "Test invalid Host",
			Args:          []string{"certify", "-connect", "1.1.1.1"},
			ExpectedError: "missing port in address",
		},
		{
			Name:          "Test no Host",
			Args:          []string{"certify", "-connect"},
			ExpectedError: "you must provide remote host",
		},
	}

	for _, tt := range tests {
		result, err := readRemoteCertificate(tt.Args)
		if err != nil {
			if !strings.Contains(err.Error(), tt.ExpectedError) {
				t.Fatalf("got %v want %v", err.Error(), tt.ExpectedError)
			}
		}

		if !strings.Contains(result, tt.ExpectedOutput) {
			t.Fatalf("certificate doesn't containing %s", tt.ExpectedOutput)
		}
	}
}

func TestMatchCertificate(t *testing.T) {
	tests := []struct {
		Name          string
		Args          []string
		expectedError string
	}{
		{
			Name: "Test when certificate and private key match",
			Args: []string{"certify", "-match", "testdata/ca-key.pem", "testdata/ca-cert.pem"},
		},
		{
			Name:          "Test when certificate and private key doesnt match",
			Args:          []string{"certify", "-match", "testdata/ca-key.pem", "testdata/nothinux.pem"},
			expectedError: "private key doesn't match with given certificate",
		},
		{
			Name:          "Test when no private key",
			Args:          []string{"certify", "-match", "testdata/ca-cert.pem"},
			expectedError: "you must provide pkey and cert",
		},
	}

	for _, tt := range tests {
		if err := matchCertificate(tt.Args); err != nil {
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Fatalf("got %v, want %v", err.Error(), tt.expectedError)
			}
		}
	}
}

func TestCreateCertificate(t *testing.T) {
	t.Run("Test create certificate with no existing CA", func(t *testing.T) {
		if err := createCertificate([]string{"certify", "127.0.0.1", "nothinux.local"}); err != nil {
			if !strings.Contains(err.Error(), "open ca-key.pem: no such file or directory") {
				t.Fatalf("got %v, want open ca-key.pem: no such file or directory", err.Error())
			}
		}
	})

	t.Run("Test create certificate", func(t *testing.T) {
		if err := initCA([]string{"certify", "-init"}); err != nil {
			t.Fatal(err)
		}

		if err := createCertificate([]string{"certify", "127.0.0.1", "nothinux.local"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Cleanup(func() {
		os.Remove(caPath)
		os.Remove(caKeyPath)
		os.Remove("nothinux.local.pem")
		os.Remove("nothinux.local-key.pem")
	})
}

func TestCreateIntermediateCertificate(t *testing.T) {
	t.Run("Test create intermediate certificate", func(t *testing.T) {
		if err := initCA([]string{"certify", "-init"}); err != nil {
			t.Fatal(err)
		}

		if err := createIntermediateCertificate([]string{"certify", "-intermediate", "cn:nothinux"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Cleanup(func() {
		os.Remove(caPath)
		os.Remove(caKeyPath)
		os.Remove(caInterPath)
		os.Remove(caInterKeyPath)
	})
}

func TestExportCertificate(t *testing.T) {
	tests := []struct {
		Name          string
		Args          []string
		Password      string
		expectedError string
	}{
		{
			Name:     "Test export certificate",
			Args:     []string{"certify", "-match", "testdata/server-key.pem", "testdata/server.pem", "testdata/ca-cert.pem"},
			Password: "password",
		},
		{
			Name:          "Test export certificate with invalid private key",
			Args:          []string{"certify", "-match", "testdata/key.pem", "testdata/server.pem", "testdata/ca-cert.pem"},
			Password:      "password",
			expectedError: "no such file or directory",
		},
		{
			Name:          "Test export certificate doesn't match with private key",
			Args:          []string{"certify", "-match", "testdata/server-key.pem", "testdata/nothinux.pem", "testdata/ca-cert.pem"},
			Password:      "password",
			expectedError: "private key doesn't match with given certificate",
		},
		{
			Name:          "Test export with wrong argument",
			Args:          []string{"certify", "-match", "testdata/server.pem", "testdata/server-key.pem", "testdata/ca-cert.pem"},
			Password:      "password",
			expectedError: "failed to parse EC private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if err := exportCertificate(tt.Args, []byte(tt.Password)); err != nil {
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Fatalf("the error must be contain %s, got %v", tt.expectedError, err)
				}
			}
		})

		t.Cleanup(func() {
			os.Remove("client.p12")
		})
	}

}
