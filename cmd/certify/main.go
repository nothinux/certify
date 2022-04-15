package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/nothinux/certify"
	"golang.org/x/term"
)

const usage = `             _   _ ___     
 ___ ___ ___| |_|_|  _|_ _ 
|  _| -_|  _|  _| |  _| | |
|___|___|_| |_| |_|_| |_  |
                      |___|

Usage of certify:
certify [flag] [ip-or-dns-san] [cn:default certify] [expiry: s,m,h,d]

$ certify -init
⚡️ Initialize new CA Certificate and Key

You must create new CA by run -init before you can create certificate.

$ certify server.local 172.17.0.1
⚡️ Generate certificate with alt name server.local and 172.17.0.1

$ certify cn:web-server
⚡️ Generate certificate with common name web-server

$ certify server.local expiry:1d
⚡️ Generate certificate expiry within 1 day

$ certify server.local eku:serverAuth,clientAuth
⚡️ Generate certificate with extended key usage Server Auth and Client Auth

Also, you can see information from certificate

$ certify -read server.local.pem
⚡️ Read certificate information from file server.local.pem

$ certify -connect google.com:443
⚡️ Show certificate information from remote host

Export certificate and private key file to pkcs12 format
$ certify -export-p12 cert.pem cert-key.pem ca-cert.pem
⚡️ Generate client.p12 pem file containing certificate, private key and ca certificate

Verify private key matches a certificate
$ certify -match cert-key.pem cert.pem
⚡️ verify cert-key.pem and cert.pem has same public key
`

var (
	caPath     = "ca-cert.pem"
	caKeyPath  = "ca-key.pem"
	Version    = "No version provided"
	initialize = flag.Bool("init", false, "initialize new CA Certificate and Key")
	read       = flag.Bool("read", false, "read information from certificate")
	match      = flag.Bool("match", false, "check if private key match with certificate")
	ver        = flag.Bool("version", false, "see program version")
	connect    = flag.Bool("connect", false, "show information about certificate on remote host")
	epkcs12    = flag.Bool("export-p12", false, "export certificate and key to pkcs12 format")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("Certify version v%s\n", Version)
		return
	}

	if *initialize {
		pkey, err := generatePrivateKey(caKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("CA private key file generated", caKeyPath)

		var cn string

		if len(os.Args) > 2 {
			if strings.Contains(os.Args[2], "cn:") {
				cn = os.Args[2]
			}
		}

		if err := generateCA(pkey.PrivateKey, cn, caPath); err != nil {
			log.Fatal(err)
		}
		fmt.Println("CA certificate file generated", caPath)
		return
	}

	if *read {
		var certByte []byte
		var err error

		if len(os.Args) < 3 {
			if err := isPipe(os.Stdin); err != nil {
				log.Fatal(err)
			}

			certByte, err = io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			certByte, err = os.ReadFile(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}
		}

		cert, err := certify.ParseCertificate(certByte)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", certify.CertInfo(cert))
		return
	}

	if *connect {
		if len(os.Args) < 3 {
			fmt.Printf("you must provide remote host.\n")
			os.Exit(1)
		}

		result, err := tlsDial(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(certify.CertInfo(result))
		return
	}

	if *match {
		if len(os.Args) < 4 {
			fmt.Printf("you must provide pkey and cert.\n")
			os.Exit(1)
		}

		pubkey, pubcert, err := matcher(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf(
			"pubkey from %s:\n%s\n\npubkey from %s:\n%s\n✅ certificate and private key match\n",
			os.Args[2],
			pubkey,
			os.Args[3],
			pubcert,
		)

		return
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

		// verify if cert and key has same public key
		_, _, err = matcher(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal("\n", err)
		}

		pfxData, err := getPfxData(
			os.Args[2],
			os.Args[3],
			os.Args[4],
			string(bytePass),
		)
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile("client.p12", pfxData, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("\ncertificate exporter to client.p12")
		return
	}

	if len(os.Args) < 2 {
		fmt.Printf("you must provide at least two argument.\n\n")
		fmt.Fprint(flag.CommandLine.Output(), usage)
		os.Exit(1)
	}

	if !isExist(caPath) || !isExist(caKeyPath) {
		log.Fatal("error CA Certificate or Key is not exists, run -init to create it.")
	}

	keyPath := getFilename(os.Args, true)

	pkey, err := generatePrivateKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Private key file generated", keyPath)

	if err := generateCert(pkey.PrivateKey, os.Args); err != nil {
		log.Fatal(err)
	}
}
