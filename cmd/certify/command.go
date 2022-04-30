package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/nothinux/certify"
	"golang.org/x/term"
)

// initCA create private key and certificate for certificate authority
func initCA(args []string) error {
	pkey, err := generatePrivateKey(caKeyPath)
	if err != nil {
		return err
	}
	fmt.Println("CA private key file generated", caKeyPath)

	var cn string

	if len(args) < 3 {
		cn = "cn:"
	} else {
		if strings.Contains(args[2], "cn:") {
			cn = args[2]
		} else {
			cn = "cn:"
		}
	}

	if err := generateCA(pkey.PrivateKey, cn, caPath); err != nil {
		return err
	}

	fmt.Println("CA certificate file generated", caPath)
	return nil
}

// readCertificate read certificate from stdin or from file
func readCertificate(args []string, stdin *os.File) (string, error) {
	var certByte []byte
	var err error

	if len(args) < 3 {
		if err := isPipe(stdin); err != nil {
			return "", err
		}

		certByte, err = io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
	} else {
		certByte, err = os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
	}

	cert, err := certify.ParseCertificate(certByte)
	if err != nil {
		return "", err
	}

	return certify.CertInfo(cert), nil
}

// readRemoteCertificate read certificate from remote host
func readRemoteCertificate(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("you must provide remote host.\n")
	}

	result, err := tlsDial(args[2])
	if err != nil {
		return "", err
	}

	return certify.CertInfo(result), nil
}

// matchCertificate math certificate with private key
func matchCertificate(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("you must provide pkey and cert")
	}

	pubkey, pubcert, err := matcher(args[2], args[3])
	if err != nil {
		return err
	}

	fmt.Printf(
		"pubkey from %s:\n%s\n\npubkey from %s:\n%s\n✅ certificate and private key match\n",
		args[2],
		pubkey,
		args[3],
		pubcert,
	)

	return nil
}

func exportCertificate(args []string) {
	if len(args) < 5 {
		fmt.Println("you must provide [key-path] [cert-path] and [ca-path]")
		os.Exit(1)
	}

	fmt.Print("enter password: ")
	bytePass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	// verify if cert and key has same public key
	_, _, err = matcher(args[2], args[3])
	if err != nil {
		log.Fatal("\n", err)
	}

	pfxData, err := getPfxData(
		args[2],
		args[3],
		args[4],
		string(bytePass),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("client.p12", pfxData, 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\ncertificate exported to client.p12")
}
