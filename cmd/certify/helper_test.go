package main

import (
	"net"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		Name        string
		Args        []string
		expectedIP  []net.IP
		expectedDNS []string
		expectedCN  string
	}{
		{
			Name:        "Test with ip and dns names",
			Args:        []string{"certify", "127.0.0.1", "172.16.0.1", "example.com"},
			expectedIP:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.16.0.1")},
			expectedDNS: []string{"example.com"},
		},
		{
			Name:        "Test only dns names",
			Args:        []string{"certify", "example.com"},
			expectedDNS: []string{"example.com"},
		},
		{
			Name:        "test with ip, dns and common name",
			Args:        []string{"certify", "cn:manager", "172.16.0.1", "example.com"},
			expectedIP:  []net.IP{net.ParseIP("172.16.0.1")},
			expectedDNS: []string{"example.com"},
			expectedCN:  "manager",
		},
		{
			Name:       "test with multiple ip",
			Args:       []string{"certify", "172.16.0.1", "192.168.0.1"},
			expectedIP: []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("192.168.0.1")},
		},
		{
			Name:        "test with multiple dns",
			Args:        []string{"certify", "sub.example.com", "srv.example.com", "example.com"},
			expectedDNS: []string{"sub.example.com", "srv.example.com", "example.com"},
		},
		{
			Name:       "test with multiple common name",
			Args:       []string{"certify", "cn:srv.example.com", "cn:example.com"},
			expectedCN: "srv.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ips, dns, cn, _, _ := parseArgs(tt.Args)

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
