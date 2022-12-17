package main

import (
	"fmt"
	"io"
	"os"

	"github.com/nothinux/certify"
)

// initCA create private key and certificate for certificate authority
func initCA(args []string) error {
	pkey, err := generatePrivateKey(caKeyPath)
	if err != nil {
		return err
	}
	fmt.Println("CA private key file generated", caKeyPath)

	if err := generateCA(pkey.PrivateKey, args, caPath); err != nil {
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
		return "", fmt.Errorf("you must provide remote host")
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

// exportCertificate export certificate to pkcs12 format
func exportCertificate(args []string, bytePass []byte) error {
	// verify if cert and key has same public key
	_, _, err := matcher(args[2], args[3])
	if err != nil {
		return err
	}

	pfxData, err := getPfxData(
		args[2],
		args[3],
		args[4],
		string(bytePass),
	)
	if err != nil {
		return err
	}

	if err := os.WriteFile("client.p12", pfxData, 0644); err != nil {
		return err
	}
	fmt.Println("\ncertificate exported to client.p12")
	return nil
}

// createCertificate generate certificate and signed with existing CA
func createCertificate(args []string) error {
	keyPath := getFilename(args, true)

	pkey, err := generatePrivateKey(keyPath)
	if err != nil {
		return err
	}

	fmt.Println("Private key file generated", keyPath)

	if err := generateCert(pkey.PrivateKey, args); err != nil {
		return err
	}

	return nil
}

// createIntermediateCertificate generate intermediate certificate and signed with existing root CA
func createIntermediateCertificate(args []string) error {
	pkey, err := generatePrivateKey(caInterKeyPath)
	if err != nil {
		return err
	}

	fmt.Println("Private key file generated", caInterKeyPath)

	if err := generateIntermediateCert(pkey.PrivateKey, args); err != nil {
		return err
	}

	return nil
}
