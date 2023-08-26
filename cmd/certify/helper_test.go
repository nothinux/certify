package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestGeneratePrivateKeyAndCA(t *testing.T) {
	pkey, err := generatePrivateKey(caKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := generateCA(pkey.PrivateKey, []string{"cn:local"}, caPath); err != nil {
		t.Fatal(err)
	}

	t.Run("Test create certificate", func(t *testing.T) {
		cpkey, err := generatePrivateKey("/tmp/pkey.pem")
		if err != nil {
			t.Fatal(err)
		}

		if err := generateCert(cpkey.PrivateKey, []string{"127.0.0.1", "local.dev", "cn:server", "expiry:1d", "eku:serverauth"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Test create intermediate certificate with attribute", func(t *testing.T) {
		ikey, err := generatePrivateKey(caInterKeyPath)
		if err != nil {
			t.Fatal(err)
		}

		if err := generateIntermediateCert(ikey.PrivateKey, []string{"cn:nothinux", "expiry:100d"}); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			cleanupfiles([]string{
				caInterPath, caInterKeyPath,
			})
		})
	})

	t.Run("Test create intermediate certificate and certificate", func(t *testing.T) {
		ikey, err := generatePrivateKey(caInterKeyPath)
		if err != nil {
			t.Fatal(err)
		}

		if err := generateIntermediateCert(ikey.PrivateKey, []string{""}); err != nil {
			t.Fatal(err)
		}

		pkey, err := generatePrivateKey("/tmp/pkey-2.pem")
		if err != nil {
			t.Fatal(err)
		}

		if err := generateCert(pkey.PrivateKey, []string{"127.0.0.1", "local-2.dev", "cn:server-2", "expiry:1d", "eku:serverauth"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Test export certificate to pkcs12", func(t *testing.T) {
		_, err := getPfxData("/tmp/pkey.pem", "local.dev.pem", "ca-cert.pem", "p4ssw0rd")
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Cleanup(func() {
		cleanupfiles([]string{
			caPath, caKeyPath, caInterPath, caInterKeyPath, caKeyPath, "local.dev.pem", "/tmp/pkey.pem", "local-2.dev.pem", "/tmp/pkey-2.pem",
		})
	})
}

func cleanupfiles(paths []string) {
	for _, path := range paths {
		os.Remove(path)
	}
}

func TestMatcher(t *testing.T) {
	t.Run("Test valid certificate and private key", func(t *testing.T) {
		pubkey, privkey, err := matcher("testdata/ca-key.pem", "testdata/ca-cert.pem")

		if err != nil {
			t.Fatalf("the private key and certificate must be match\n%v\n%v", pubkey, privkey)
		}
	})
	t.Run("Test invalid certificate and private key path", func(t *testing.T) {
		_, _, err := matcher("ca-key.pem", "ca-cert.pem")

		if err == nil {
			t.Fatalf("the matcher must be error, because the path is invalid")
		}
	})
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		Name                 string
		Args                 []string
		expectedIP           []net.IP
		expectedDNS          []string
		expectedCN           string
		expectedOrganization string
		expectedExpiry       time.Time
		expectedEku          []x509.ExtKeyUsage
	}{
		{
			Name:                 "Test with ip and dns names",
			Args:                 []string{"certify", "127.0.0.1", "172.16.0.1", "example.com"},
			expectedIP:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.16.0.1")},
			expectedDNS:          []string{"example.com"},
			expectedCN:           "certify",
			expectedOrganization: "certify",
		},
		{
			Name:                 "Test only dns names",
			Args:                 []string{"certify", "example.com"},
			expectedDNS:          []string{"example.com"},
			expectedCN:           "certify",
			expectedOrganization: "certify",
		},
		{
			Name:                 "test with ip, dns and common name",
			Args:                 []string{"certify", "cn:manager", "172.16.0.1", "example.com"},
			expectedIP:           []net.IP{net.ParseIP("172.16.0.1")},
			expectedDNS:          []string{"example.com"},
			expectedCN:           "manager",
			expectedOrganization: "certify",
		},
		{
			Name:                 "test with multiple ip",
			Args:                 []string{"certify", "172.16.0.1", "192.168.0.1"},
			expectedIP:           []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("192.168.0.1")},
			expectedCN:           "certify",
			expectedOrganization: "certify",
		},
		{
			Name:                 "test with multiple dns",
			Args:                 []string{"certify", "sub.example.com", "srv.example.com", "example.com"},
			expectedDNS:          []string{"sub.example.com", "srv.example.com", "example.com"},
			expectedCN:           "certify",
			expectedOrganization: "certify",
		},
		{
			Name:                 "test with common name",
			Args:                 []string{"certify", "cn:example.com"},
			expectedCN:           "example.com",
			expectedOrganization: "certify",
		},
		{
			Name:                 "test with organization",
			Args:                 []string{"certify", "o:nothinux"},
			expectedCN:           "certify",
			expectedOrganization: "nothinux",
		},
		{
			Name:                 "test with common name and organization",
			Args:                 []string{"certify", "cn:server", "o:nothinux"},
			expectedCN:           "server",
			expectedOrganization: "nothinux",
		},
		{
			Name:                 "test with multiple common name",
			Args:                 []string{"certify", "cn:srv.example.com", "cn:example.com"},
			expectedCN:           "srv.example.com",
			expectedOrganization: "certify",
		},
		{
			Name:                 "Test with expiry 12 hours",
			Args:                 []string{"certify", "sub.example.local", "expiry:12h"},
			expectedExpiry:       time.Now().Add(12 * time.Hour),
			expectedCN:           "certify",
			expectedOrganization: "certify",
		},
		{
			Name:                 "Test with expiry 30 days",
			Args:                 []string{"certify", "cn:server", "expiry:30d"},
			expectedExpiry:       time.Now().Add(30 * 24 * time.Hour),
			expectedCN:           "server",
			expectedOrganization: "certify",
		},
		{
			Name: "Test with custom ekus",
			Args: []string{"certify", "cn:client", "eku:serverauth,codesigning"},
			expectedEku: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageCodeSigning,
			},
			expectedCN:           "client",
			expectedOrganization: "certify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ips, dns, cn, o, expiry, ekus := parseArgs(tt.Args)

			if len(tt.expectedIP) != 0 {
				for i, ip := range ips {
					if !ip.Equal(tt.expectedIP[i]) {
						t.Fatalf("got %v, want %v", ip, tt.expectedIP[i])
					}
				}
			}

			if len(tt.expectedDNS) != 0 {
				for i, d := range dns {
					if d != tt.expectedDNS[i] {
						t.Fatalf("got %v, want %v", d, tt.expectedDNS[i])
					}
				}
			}

			if cn != tt.expectedCN {
				t.Fatalf("got %v, want %v", cn, tt.expectedCN)
			}

			if o != tt.expectedOrganization {
				t.Fatalf("got %v, want %v", o, tt.expectedOrganization)
			}

			if !tt.expectedExpiry.IsZero() {
				if expiry.Unix() != tt.expectedExpiry.Unix() {
					t.Fatalf("got %v, want %v", expiry.Unix(), tt.expectedExpiry.Unix())
				}
			} else {
				if expiry.Unix() != time.Now().Add(8766*time.Hour).Unix() {
					t.Fatalf("got %v, want %v", expiry.Unix(), time.Now().Add(8766*time.Hour).Unix())
				}
			}

			if len(tt.expectedEku) != 0 {
				if !reflect.DeepEqual(ekus, tt.expectedEku) {
					t.Fatalf("fot %v, want %v", ekus, tt.expectedEku)
				}
			} else {
				defaultEku := []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageServerAuth,
				}

				if !reflect.DeepEqual(ekus, defaultEku) {
					t.Fatalf("got %v, want %v", ekus, defaultEku)
				}
			}
		})
	}
}

func TestGetFilename(t *testing.T) {
	tests := []struct {
		Name         string
		Args         []string
		Key          bool
		expectedPath string
	}{
		{
			Name:         "private key with ip",
			Args:         []string{"certify", "127.0.0.1"},
			Key:          true,
			expectedPath: "127.0.0.1-key.pem",
		},
		{
			Name:         "private key with multiple ip",
			Args:         []string{"certify", "127.0.0.1", "182.0.0.1"},
			Key:          true,
			expectedPath: "127.0.0.1-key.pem",
		},
		{
			Name:         "certificate with multiple ip",
			Args:         []string{"certify", "127.0.0.1", "182.0.0.1"},
			Key:          false,
			expectedPath: "127.0.0.1.pem",
		},
		{
			Name:         "certificate with dns",
			Args:         []string{"certify", "example.com"},
			Key:          false,
			expectedPath: "example.com.pem",
		},
		{
			Name:         "certificate with dns and ip",
			Args:         []string{"certify", "example.com", "127.0.0.1"},
			Key:          false,
			expectedPath: "example.com.pem",
		},
		{
			Name:         "certificate with ip and dns",
			Args:         []string{"certify", "127.0.0.1", "example.com"},
			Key:          false,
			expectedPath: "example.com.pem",
		},
		{
			Name:         "certificate with ip and dns and common name",
			Args:         []string{"certify", "127.0.0.1", "example.com", "cn:web"},
			Key:          false,
			expectedPath: "example.com.pem",
		},
		{
			Name:         "certificate with common name and ip",
			Args:         []string{"certify", "cn:web", "127.0.0.1"},
			Key:          false,
			expectedPath: "127.0.0.1.pem",
		},
		{
			Name:         "certificate with common name",
			Args:         []string{"certify", "cn:web"},
			Key:          false,
			expectedPath: "web.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			path := getFilename(tt.Args, tt.Key)

			if path != tt.expectedPath {
				t.Fatalf("got %v, want %v", path, tt.expectedPath)
			}
		})
	}
}

func TestParseString(t *testing.T) {
	tests := []struct {
		Name                 string
		CN                   string
		ExpectedCN           string
		Organization         string
		ExpectedOrganization string
	}{
		{
			Name:       "Test valid common name",
			CN:         "cn:server",
			ExpectedCN: "server",
		},
		{
			Name:       "Test empty common name",
			CN:         "cn:",
			ExpectedCN: "certify",
		},
		{
			Name:                 "Test valid organization",
			Organization:         "o:nothinux",
			ExpectedOrganization: "nothinux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.CN != "" {
				parsedCN := parseString(tt.CN)

				if parsedCN != tt.ExpectedCN {
					t.Fatalf("got %v, want %v", parsedCN, tt.ExpectedCN)
				}
			}

			if tt.Organization != "" {
				parsedOrganization := parseString(tt.Organization)

				if parsedOrganization != tt.ExpectedOrganization {
					t.Fatalf("got %v, want %v", parsedOrganization, tt.ExpectedOrganization)
				}
			}
		})
	}
}

func TestParseEKU(t *testing.T) {
	tests := []struct {
		Name        string
		Eku         string
		ExpectedEku []x509.ExtKeyUsage
	}{
		{
			Name: "Test eku serverauth",
			Eku:  "eku:serverAuth",
			ExpectedEku: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
		},
		{
			Name: "Test eku client auth and code signing",
			Eku:  "eku:clientAuth,codesigning",
			ExpectedEku: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
			},
		},
		{
			Name: "Test all eku",
			Eku:  "eku:serverauth,clientauth,any,codesigning,emailprotection,ipsecendsystem,ipsectunnel,ipsecuser,timestamping,ocspsigning,microsoftservergatedcrypto,netscapeservergatedcrypto,microsoftcommercialcodesigning,microsoftkernelcodesigning",
			ExpectedEku: []x509.ExtKeyUsage{
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
			},
		},
		{
			Name:        "Test empty eku",
			Eku:         "eku:",
			ExpectedEku: []x509.ExtKeyUsage{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			parsedEku := parseEKU(tt.Eku)

			if len(parsedEku) == 0 {
				if len(parsedEku) != len(tt.ExpectedEku) {
					t.Fatalf("got %v, want %v", len(parsedEku), len(tt.ExpectedEku))
				}
				return
			}

			if !reflect.DeepEqual(parsedEku, tt.ExpectedEku) {
				t.Fatalf("got %v, want %v", parsedEku, tt.ExpectedEku)
			}
		})
	}
}

func TestParseExpiry(t *testing.T) {
	tests := []struct {
		Name         string
		Time         string
		ExpectedTime time.Time
	}{
		{
			Name:         "Test 5 seconds",
			Time:         "expiry:5s",
			ExpectedTime: time.Now().Add(5 * time.Second),
		},
		{
			Name:         "Test 10 minutes",
			Time:         "expiry:10m",
			ExpectedTime: time.Now().Add(10 * time.Minute),
		},
		{
			Name:         "Test 5 hours",
			Time:         "expiry:5h",
			ExpectedTime: time.Now().Add(5 * time.Hour),
		},
		{
			Name:         "Test 7 days",
			Time:         "expiry:7d",
			ExpectedTime: time.Now().Add(7 * 24 * time.Hour),
		},
		{
			Name:         "Test 2 years",
			Time:         "expiry:2y",
			ExpectedTime: time.Now().Add(8766 * time.Hour),
		},
		{
			Name:         "Test no time",
			Time:         "expiry:",
			ExpectedTime: time.Now().Add(8766 * time.Hour),
		},
		{
			Name:         "Test wrong format",
			Time:         "expiry:od",
			ExpectedTime: time.Now().Add(8766 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result := parseExpiry(tt.Time)

			if result.Unix() != tt.ExpectedTime.Unix() {
				t.Fatalf("got %v, want %v", result.Unix(), tt.ExpectedTime.Unix())
			}
		})

	}
}

func TestIsExist(t *testing.T) {
	t.Run("Test if path is exists", func(t *testing.T) {
		if err := os.Mkdir("/tmp/randpath", 0755); err != nil {
			t.Fatal(err)
		}

		if !isExist("/tmp/randpath") {
			t.Fatalf("path must be exists")
		}

		if err := os.Remove("/tmp/randpath"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Test if path is not exists", func(t *testing.T) {
		if isExist("/tmp/xxx/yyy/zzz") {
			t.Fatalf("path must be doesn't exists")
		}
	})
}

func TestTlsDial(t *testing.T) {
	t.Run("Test valid host", func(t *testing.T) {
		_, err := tlsDial("google.com:443", &tls.Config{})
		if err != nil {
			t.Fatalf("the dial must be success %v", err)
		}
	})

	t.Run("Test Invalid host", func(t *testing.T) {
		_, err := tlsDial("google.com", &tls.Config{})
		if err == nil {
			t.Fatalf("the dial must be error")
		}
	})
}

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		Name           string
		Args           []string
		ExpectedConfig uint16
		ExpectedErr    error
	}{
		{
			Name:           "Test using tls version 1.0",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:1.0"},
			ExpectedConfig: tls.VersionTLS10,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test using tls version 1.1",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:1.1"},
			ExpectedConfig: tls.VersionTLS11,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test using tls version 1.2",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:1.2"},
			ExpectedConfig: tls.VersionTLS12,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test using tls version 1.3",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:1.3"},
			ExpectedConfig: tls.VersionTLS13,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test using not available tls version",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:1.4"},
			ExpectedConfig: tls.VersionTLS12,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test using not available tls version",
			Args:           []string{"certify", "-connect", "google.com:443", "tlsver:sslv3"},
			ExpectedConfig: tls.VersionTLS12,
			ExpectedErr:    nil,
		},
		{
			Name:           "Test without provide tls version",
			Args:           []string{"certify", "-connect", "google.com:443"},
			ExpectedConfig: tls.VersionTLS12,
			ExpectedErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			config := parseTLSVersion(tt.Args)

			if !reflect.DeepEqual(config, tt.ExpectedConfig) {
				t.Fatalf("got %v, want %v", config, tt.ExpectedConfig)
			}
		})
	}
}

func TestParseInsecureArg(t *testing.T) {
	tests := []struct {
		Name     string
		Args     []string
		Expected bool
	}{
		{
			Name:     "Test using insecure arg enabled",
			Args:     []string{"certify", "-connect", "google.com:443", "insecure"},
			Expected: true,
		},
		{
			Name:     "Test without insecure flag",
			Args:     []string{"certify", "-connect", "google.com:443", "tlsver:1.1"},
			Expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			config := parseInsecureArg(tt.Args)

			if !reflect.DeepEqual(config, tt.Expected) {
				t.Fatalf("got %v, want %v", config, tt.Expected)
			}
		})
	}
}

func TestParseCAArg(t *testing.T) {
	tests := []struct {
		Name     string
		Args     []string
		Expected string
	}{
		{
			Name:     "Test with ca arg",
			Args:     []string{"certify", "-connect", "google.com:443", "with-ca:/tmp/ca-cert.pem"},
			Expected: "/tmp/ca-cert.pem",
		},
		{
			Name:     "Test with ca arg without value",
			Args:     []string{"certify", "-connect", "google.com:443", "with-ca:"},
			Expected: "",
		},
		{
			Name:     "Test without ca arg",
			Args:     []string{"certify", "-connect", "google.com:443"},
			Expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			config := parseCAarg(tt.Args)

			if !reflect.DeepEqual(config, tt.Expected) {
				t.Fatalf("got %v, want %v", config, tt.Expected)
			}
		})
	}
}
