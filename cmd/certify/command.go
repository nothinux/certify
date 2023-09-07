package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
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

	caCert, err := generateCA(pkey.PrivateKey, args, caPath)
	if err != nil {
		return err
	}

	fmt.Println("CA certificate file generated", caPath)

	if err := generateCRL(pkey.PrivateKey, caCert.Cert); err != nil {
		return err
	}
	fmt.Println("CRL file generated", caCRLPath)

	return nil
}

// readCertificate read certificate from stdin or from file
func readCertificate(args []string, stdin *os.File) (string, error) {
	var certByte []byte
	var err error

	if len(args) < 3 {
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

// readCRL read crl from stdin or from file
func readCRL(args []string, stdin *os.File) (string, error) {
	var certByte []byte
	var err error

	if len(args) < 3 {
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

	crl, err := certify.ParseCRL(certByte)
	if err != nil {
		return "", err
	}

	return certify.CRLInfo(crl), nil
}

// readRemoteCertificate read certificate from remote host
func readRemoteCertificate(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("you must provide remote host")
	}

	tlsConfig := &tls.Config{}

	tlsVer := parseTLSVersion(args)
	tlsConfig.MinVersion = tlsVer
	tlsConfig.MaxVersion = tlsVer
	tlsConfig.InsecureSkipVerify = parseInsecureArg(args)

	caPath := parseCAarg(args)
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			log.Printf("ca-cert error %v, ignoring the ca-cert\n", err)
		}

		if err == nil {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig.RootCAs = caCertPool
		}
	}

	result, err := tlsDial(args[2], tlsConfig)
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

func verifyCertificate(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("you need to provide cert file and crl file")
	}

	cert, err := readCertificateFile(args[2])
	if err != nil {
		return err
	}

	crl, err := readCRLFile(args[3])
	if err != nil {
		return err
	}

	for _, sn := range crl.RevokedCertificateEntries {
		if sn.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			fmt.Printf("%s\ncode: %d\ncertificate revoked at %v\n", cert.Subject.String(), sn.ReasonCode, sn.RevocationTime.Format("2006-01-02 15:04:05"))
			return fmt.Errorf("error %s verification failed", args[2])
		}
	}

	fmt.Printf("%s: OK\n", args[2])
	return nil
}

func revokeCertificate(args []string) (string, error) {
	if len(args) < 4 {
		return "", fmt.Errorf("you need to provide cert file and crl file")
	}

	crlBytes, err := os.ReadFile(args[3])
	if err != nil {
		return "", err
	}

	cert, err := readCertificateFile(args[2])
	if err != nil {
		return "", err
	}

	caCert, err := getCACert(caPath)
	if err != nil {
		return "", err
	}

	pkey, err := getCAPrivateKey(caKeyPath)
	if err != nil {
		return "", err
	}

	fmt.Printf("revoking certificate cn=%s o=%s with serial number %s\n", cert.Subject.CommonName, cert.Subject.Organization, cert.SerialNumber)
	crl, crlNum, err := certify.RevokeCertificate(crlBytes, cert, caCert, pkey)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("ca-crl-%s.pem", crlNum)

	fmt.Printf("CA CRL file generated %s\n", path)
	return path, store(crl.String(), path)
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
