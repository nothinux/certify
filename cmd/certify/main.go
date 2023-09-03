package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/term"
)

var usage = `             _   _ ___     
 ___ ___ ___| |_|_|  _|_ _ 
|  _| -_|  _|  _| |  _| | |
|___|___|_| |_| |_|_| |_  |
                      |___| Certify v%s

Usage of certify:
certify [flag] [ip-or-dns-san] [cn:default certify] [o: default certify] [eku:default serverAuth,clientAuth] [expiry:default 8766h s,m,h,d]

$ certify server.local 172.17.0.1 cn:web-server eku:serverAuth expiry:1d

Flags:
  -init
	Initialize new root CA Certificate and Key
  -intermediate
	Generate intermediate certificate
  -read  <filename>
	Read certificate information from file or stdin
  -read-crl <filename>
    Read certificate revocation list from file or stdin
  -connect  <host:443> <tlsver:1.2> <insecure> <with-ca:ca-path>
	Show certificate information from remote host, use tlsver to set spesific tls version
  -export-p12  <cert> <private-key> <ca-cert>
	Generate client.p12 pem file containing certificate, private key and ca certificate
  -match  <private-key> <cert>
	Verify cert-key.pem and cert.pem has same public key
  -interactive
    Run certify interactively
  -revoke <ca-cert> <ca-private-key>
    Revoke certificate, the certificate will be added to CRL
  -version
	print certify version
`

var (
	caPath         = "ca-cert.pem"
	caKeyPath      = "ca-key.pem"
	caCRLPath      = "ca-crl.pem"
	caInterPath    = "ca-intermediate.pem"
	caInterKeyPath = "ca-intermediate-key.pem"
	Version        = "No version provided"
)

func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}

func runMain() error {
	var (
		initialize   = flag.Bool("init", false, "initialize new root CA Certificate and Key")
		intermediate = flag.Bool("intermediate", false, "create intermediate certificate")
		read         = flag.Bool("read", false, "read information from certificate")
		readcrl      = flag.Bool("read-crl", false, "read information from certificate revocation list")
		match        = flag.Bool("match", false, "check if private key match with certificate")
		ver          = flag.Bool("version", false, "see program version")
		connect      = flag.Bool("connect", false, "show information about certificate on remote host")
		epkcs12      = flag.Bool("export-p12", false, "export certificate and key to pkcs12 format")
		interactive  = flag.Bool("interactive", false, "run certify interactively")
		revoke       = flag.Bool("revoke", false, "Revoke certificate, the certificate will be added to CRL")
	)

	flag.Usage = func() {
		showUsage := fmt.Sprintf(usage, Version)
		fmt.Fprint(flag.CommandLine.Output(), showUsage)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("Certify version v%s\n", Version)
		return nil
	}

	if *initialize {
		if err := initCA(os.Args); err != nil {
			return err
		}
		return nil
	}

	if *read {
		cert, err := readCertificate(os.Args, os.Stdin)
		if err != nil {
			return err
		}
		fmt.Printf("%s", cert)
		return nil
	}

	if *readcrl {
		crl, err := readCRL(os.Args, os.Stdin)
		if err != nil {
			return err
		}
		fmt.Printf("%s", crl)
		return nil
	}

	if *connect {
		result, err := readRemoteCertificate(os.Args)
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}

	if *match {
		if err := matchCertificate(os.Args); err != nil {
			return err
		}
		return nil
	}

	if *interactive {
		return runWizard()
	}

	if *revoke {
		return revokeCertificate(os.Args)
	}

	if *epkcs12 {
		if len(os.Args) < 5 {
			fmt.Println("you must provide [key-path] [cert-path] and [ca-path]")
			os.Exit(1)
		}

		fmt.Print("enter password: ")
		bytePass, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		}

		if err := exportCertificate(os.Args, bytePass); err != nil {
			return err
		}

		return nil
	}

	if len(os.Args) < 2 {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		return fmt.Errorf("you must provide at least two argument")
	}

	if !isExist(caPath) || !isExist(caKeyPath) {
		return fmt.Errorf("error CA Certificate or Key is not exists, run -init to create it")
	}

	if *intermediate {
		if err := createIntermediateCertificate(os.Args); err != nil {
			return err
		}
		return nil
	}

	if err := createCertificate(os.Args); err != nil {
		return err
	}

	return nil
}
