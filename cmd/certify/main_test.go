package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func TestRunMain(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		Name          string
		Args          []string
		expectedError string
		PreRun        func()
		RunCheck      func()
	}{
		{
			Name:     "Test -version flag",
			Args:     []string{"-version"},
			PreRun:   func() {},
			RunCheck: func() {},
		},
		{
			Name:   "Test -init flag",
			Args:   []string{"-init"},
			PreRun: func() {},
			RunCheck: func() {
				if !isExist(caPath) {
					t.Fatalf("%s must be exists", caPath)
				}
				if !isExist(caKeyPath) {
					t.Fatalf("%s must be exists", caKeyPath)
				}

				os.Remove(caPath)
				os.Remove(caKeyPath)
			},
		},
		{
			Name:   "Test -init flag with cn",
			Args:   []string{"-init", "cn:nothinux"},
			PreRun: func() {},
			RunCheck: func() {
				if !isExist(caPath) {
					t.Fatalf("%s must be exists", caPath)
				}
				if !isExist(caKeyPath) {
					t.Fatalf("%s must be exists", caKeyPath)
				}

				os.Remove(caPath)
				os.Remove(caKeyPath)
			},
		},
		{
			Name:   "Test -read flag with filename",
			Args:   []string{"-read", "testdata/nothinux.pem"},
			PreRun: func() {},
			RunCheck: func() {
				cert, err := readCertificate([]string{"certify", "-read", "testdata/nothinux.pem"}, nil)
				if err != nil {
					t.Fatal(err)
				}

				if !strings.Contains(cert, "Subject: CN=nothinux, O=certify") {
					t.Fatalf("certificate doesn't contain Subject: CN=nothinux, O=certify")
				}
			},
		},
		{
			Name:          "Test -read flag with doesn't exist file",
			Args:          []string{"-read", "nothinux.pem"},
			PreRun:        func() {},
			RunCheck:      func() {},
			expectedError: "no such file or directory",
		},
		{
			Name:     "Test -connect flag with valid host",
			Args:     []string{"-connect", "google.com:443"},
			PreRun:   func() {},
			RunCheck: func() {},
		},
		{
			Name:          "Test -connect flag with invalid host",
			Args:          []string{"-connect", "google.com"},
			PreRun:        func() {},
			RunCheck:      func() {},
			expectedError: "missing port in address",
		},
		{
			Name:     "Test -match flag",
			Args:     []string{"-match", "testdata/ca-key.pem", "testdata/ca-cert.pem"},
			PreRun:   func() {},
			RunCheck: func() {},
		},
		{
			Name:          "Test -match flag with wrong certificate",
			Args:          []string{"-match", "testdata/ca-key.pem", "testdata/nothinux.pem"},
			PreRun:        func() {},
			RunCheck:      func() {},
			expectedError: "private key doesn't match with given certificate",
		},
		{
			Name:          "Test no argument",
			Args:          []string{},
			PreRun:        func() {},
			RunCheck:      func() {},
			expectedError: "you must provide at least two argument",
		},
		{
			Name:          "Test create certificate when existing CA doesn't exists",
			Args:          []string{"127.0.0.1", "cn:nothinux"},
			PreRun:        func() {},
			RunCheck:      func() {},
			expectedError: "error CA Certificate or Key is not exists, run -init to create it",
		},
		{
			Name: "Test create intermediate certificate",
			Args: []string{"-intermediate", "cn:nothinux"},
			PreRun: func() {
				if err := initCA([]string{"certify", "-init"}); err != nil {
					t.Fatal(err)
				}
			},
			RunCheck: func() {
				cert, err := readCertificate([]string{"certify", "-read", caInterPath}, nil)
				if err != nil {
					t.Fatal(err)
				}

				if !strings.Contains(cert, "Subject: CN=nothinux Intermediate, O=certify") {
					t.Fatalf("certificate doesn't contain Subject: CN=nothinux Intermediate, O=certify got %v", cert)
				}

				os.Remove(caPath)
				os.Remove(caKeyPath)
				os.Remove(caInterPath)
				os.Remove(caInterKeyPath)
			},
		},
		{
			Name: "Test create certificate",
			Args: []string{"127.0.0.1", "nothinux", "cn:nothinux"},
			PreRun: func() {
				if err := initCA([]string{"certify", "-init"}); err != nil {
					t.Fatal(err)
				}
			},
			RunCheck: func() {
				cert, err := readCertificate([]string{"certify", "-read", "nothinux.pem"}, nil)
				if err != nil {
					t.Fatal(err)
				}

				if !strings.Contains(cert, "Subject: CN=nothinux, O=certify") {
					t.Fatalf("certificate doesn't contain Subject: CN=nothinux, O=certify")
				}

				os.Remove(caPath)
				os.Remove(caKeyPath)
				os.Remove("nothinux.pem")
				os.Remove("nothinux-key.pem")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			flag.CommandLine = flag.NewFlagSet("certify", flag.ExitOnError)

			tt.PreRun()

			args := make([]string, len(tt.Args)+1)

			args[0] = "certify"
			copy(args[1:], tt.Args)

			os.Args = args

			if err := runMain(); err != nil {
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Fatalf("got %v, want %v", err.Error(), tt.expectedError)
				}
			}

			tt.RunCheck()
		})
	}

}
